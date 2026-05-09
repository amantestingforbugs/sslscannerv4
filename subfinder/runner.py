"""
subfinder/runner.py
Integrates ProjectDiscovery Subfinder with the SSL Sentinel pipeline.

How it works:
  1. Extracts root domains from project hosts and runs subfinder per root
  2. Parses stdout for discovered subdomains
  3. Deduplicates against previously stored hosts
  4. New hosts are written to subfinder_hosts table
  5. New hosts are immediately queued for SSL scanning
  6. Falls back to simulation mode if subfinder binary not found
"""

import gzip
import json
import logging
import re
import socket
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse
from core.observability import log_event

log = logging.getLogger(__name__)

SUBFINDER_BIN = shutil.which("subfinder") or "/usr/local/bin/subfinder"
_sf_lock = threading.Lock()
_sf_state = {}  # project_id -> {status, job_id, new_count}
_subfinder_all_flag_supported: Optional[bool] = None


def _resolve_subfinder_bin() -> Optional[str]:
    path = shutil.which("subfinder")
    if path:
        return path
    fallback = "/usr/local/bin/subfinder"
    return fallback if Path(fallback).exists() else None


def subfinder_available() -> bool:
    return bool(_resolve_subfinder_bin())


def _subfinder_supports_all_flag(subfinder_bin: str) -> bool:
    """
    Detect whether the installed subfinder binary supports '-all'.
    Some environments ship older builds where this flag is unavailable.
    """
    global _subfinder_all_flag_supported
    if _subfinder_all_flag_supported is not None:
        return _subfinder_all_flag_supported
    try:
        help_result = subprocess.run(
            [subfinder_bin, "-h"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        help_text = f"{help_result.stdout}\n{help_result.stderr}".lower()
        _subfinder_all_flag_supported = "-all" in help_text
    except Exception:
        # Be permissive on detection failure: prefer baseline command without -all.
        _subfinder_all_flag_supported = False
    return _subfinder_all_flag_supported


def _build_subfinder_cmd(subfinder_bin: str, root_domain: str) -> List[str]:
    cmd = [subfinder_bin, "-d", root_domain, "-silent", "-timeout", "30"]
    if _subfinder_supports_all_flag(subfinder_bin):
        cmd.append("-all")
    return cmd


def _run_subfinder_for_root(root_domain: str, timeout: int = 180) -> Dict[str, object]:
    subfinder_bin = _resolve_subfinder_bin()
    if not subfinder_bin:
        return {
            "root_domain": root_domain,
            "command": "subfinder -d <domain> -silent -timeout 30",
            "status": "error",
            "exit_code": None,
            "stdout": "",
            "stderr": "subfinder binary not found in PATH or /usr/local/bin/subfinder",
            "found": [],
        }
    cmd = _build_subfinder_cmd(subfinder_bin, root_domain)
    command_str = " ".join(cmd)
    log.info("Subfinder start (bin=%s): %s", subfinder_bin, command_str)
    log_event("subfinder", "info", "Subfinder command started", root_domain=root_domain, command=command_str, status="running")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        raw_lines = [ln.strip().lower() for ln in result.stdout.splitlines() if ln.strip()]
        found = sorted(
            {
                candidate
                for ln in raw_lines
                for candidate in [_normalize_host(ln)]
                if candidate
                and _HOST_RE.match(candidate)
                and _is_host_within_root(candidate, root_domain)
            }
        )
        status = "done" if result.returncode == 0 else "error"
        log.info(
            "Subfinder finished root=%s exit_code=%s discovered=%d",
            root_domain,
            result.returncode,
            len(found),
        )
        return {
            "root_domain": root_domain,
            "command": command_str,
            "status": status,
            "exit_code": result.returncode,
            "stdout": result.stdout or "",
            "stderr": result.stderr or "",
            "found": found,
        }
    except subprocess.TimeoutExpired:
        msg = f"Subfinder timed out after {timeout}s for {root_domain}"
        log.error(msg)
        return {
            "root_domain": root_domain,
            "command": command_str,
            "status": "timeout",
            "exit_code": None,
            "stdout": "",
            "stderr": msg,
            "found": [],
        }
    except Exception as e:
        log.exception("Subfinder execution error: %s", e)
        return {
            "root_domain": root_domain,
            "command": command_str,
            "status": "error",
            "exit_code": None,
            "stdout": "",
            "stderr": str(e),
            "found": [],
        }


_HOST_RE = re.compile(r"^(?:\*\.)?(?=.{1,253}$)(?!-)[a-z0-9-]+(?:\.[a-z0-9-]+)+$", re.IGNORECASE)
_COMMON_COMPOUND_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp",
    "com.br", "com.mx", "com.tr",
}
_BRUTE_LABELS = (
    "www", "api", "app", "admin", "dev", "test", "staging", "stage",
    "qa", "uat", "prod", "portal", "vpn", "mail", "smtp", "imap",
    "cdn", "img", "assets", "files", "docs", "status", "auth", "login",
    "gateway", "edge", "m", "beta", "shop", "blog", "mobile", "monitoring",
)


def _normalize_host(host: str) -> str:
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return ""
    if "://" in h:
        try:
            parsed = urlparse(h)
            if parsed.hostname:
                h = parsed.hostname
            else:
                h = h.split("://", 1)[1].split("/", 1)[0]
        except Exception:
            h = h.split("://", 1)[1].split("/", 1)[0]
    if h.startswith("*."):
        h = h[2:]
    if h.startswith("[") and "]" in h:
        h = h[1:h.index("]")]
    elif ":" in h:
        h = h.split(":", 1)[0]
    return h


def _registrable_domain(host: str) -> Optional[str]:
    try:
        import tldextract
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass

    parts = host.split(".")
    if len(parts) < 2:
        return None
    tail2 = ".".join(parts[-2:])
    tail3 = ".".join(parts[-3:]) if len(parts) >= 3 else ""
    if tail2 in _COMMON_COMPOUND_SUFFIXES and len(parts) >= 3:
        return tail3
    return tail2


def _extract_project_root_domains(hosts: List[str]) -> List[str]:
    """Extract registrable root domains from a project host list."""
    normalized: List[str] = []
    for raw in hosts:
        raw_line = (raw or "").strip()
        if not raw_line:
            continue
        for token in re.split(r"[\s,;]+", raw_line):
            h = _normalize_host(token)
            if not h or "." not in h or not _HOST_RE.match(h):
                continue
            normalized.append(h)

    if not normalized:
        return []

    roots: Set[str] = set()
    for h in normalized:
        root = _registrable_domain(h)
        if root:
            roots.add(root)

    return sorted(roots)


def _is_host_within_root(host: str, root_domain: str) -> bool:
    if host == root_domain:
        return True
    return host.endswith(f".{root_domain}")


def _host_resolves(host: str, timeout: float = 1.5) -> bool:
    """Resolve a host without mutating process-wide socket defaults."""

    def _resolve() -> bool:
        socket.getaddrinfo(host, None)
        return True

    with ThreadPoolExecutor(max_workers=1) as resolver:
        future = resolver.submit(_resolve)
        try:
            return future.result(timeout=timeout)
        except Exception:
            return False


def _generate_bruteforce_candidates(root_domain: str, seed_hosts: List[str]) -> Set[str]:
    candidates: Set[str] = {f"{label}.{root_domain}" for label in _BRUTE_LABELS}
    relevant = [h for h in seed_hosts if _is_host_within_root(h, root_domain)]
    for host in relevant:
        left = host[:-len(root_domain)].rstrip(".")
        if not left:
            continue
        labels = [part for part in left.split(".") if part]
        if not labels:
            continue
        last_label = labels[-1]
        for label in _BRUTE_LABELS:
            candidates.add(f"{label}.{last_label}.{root_domain}")
    return {c for c in candidates if _HOST_RE.match(c)}


def _bruteforce_dns_hosts(root_domain: str, seed_hosts: List[str], max_candidates: int = 400) -> List[str]:
    candidates = sorted(_generate_bruteforce_candidates(root_domain, seed_hosts))
    if max_candidates > 0:
        candidates = candidates[:max_candidates]
    resolved: List[str] = []
    workers = max(8, min(64, len(candidates) or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_host_resolves, host): host for host in candidates}
        for future in as_completed(futures):
            host = futures[future]
            try:
                if future.result():
                    resolved.append(host)
            except Exception:
                continue
    return sorted(set(resolved))


def _resolve_active_hosts_with_httpx(hostnames: List[str], timeout: int = 90) -> List[Dict[str, object]]:
    httpx_bin = shutil.which("httpx") or "/usr/local/bin/httpx"
    if not httpx_bin or not Path(httpx_bin).exists():
        log.warning("httpx binary not found; skipping active host enrichment")
        return []
    hosts = [h.strip().lower() for h in hostnames if (h or "").strip()]
    if not hosts:
        return []
    try:
        run = subprocess.run(
            [
                httpx_bin,
                "-silent",
                "-json",
                "-status-code",
                "-title",
                "-location",
                "-follow-host-redirects",
            ],
            input="\n".join(hosts),
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        if run.returncode != 0 and not (run.stdout or "").strip():
            log.warning("httpx returned non-zero exit=%s stderr=%s", run.returncode, (run.stderr or "").strip())
            return []
        resolved = []
        for line in (run.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            host = _normalize_host(
                row.get("host")
                or row.get("input")
                or row.get("url")
                or row.get("final_url")
                or ""
            )
            if not host:
                continue
            status_code = row.get("status_code")
            if status_code is None:
                status_code = row.get("status-code")
            try:
                status_code = int(status_code) if status_code is not None else None
            except Exception:
                status_code = None
            resolved.append(
                {
                    "hostname": host,
                    "status_code": status_code,
                    "page_title": (row.get("title") or row.get("page_title") or "").strip(),
                    "redirect_location": (row.get("location") or row.get("redirect_location") or "").strip(),
                    "final_url": (row.get("final_url") or row.get("url") or "").strip(),
                    "scheme": row.get("scheme") or "",
                    "is_active": True,
                }
            )
        return resolved
    except Exception as e:
        log.warning("httpx enrichment failed: %s", e)
        return []


def run_subfinder_for_project(project_id: str, triggered_by: str = "scheduler") -> Optional[str]:
    """
    Full subfinder pipeline for a project:
      - extract root domains from project host list
      - run subfinder
      - store new hosts
      - trigger SSL scan on new hosts
    Returns job_id or None on failure.
    """
    from db.database import (
        project_get, project_hosts, subfinder_job_create, subfinder_job_finish,
        subfinder_job_error, subfinder_hosts_add_batch, subfinder_raw_result_add,
        subfinder_raw_result_finish, subfinder_new_discoveries_add_batch,
        subfinder_httpx_results_upsert_batch,
    )

    project = project_get(project_id)
    if not project:
        return None

    hosts = project_hosts(project_id)
    if not hosts:
        log.warning("Subfinder: project '%s' has no base hosts", project["name"])
        log_event("subfinder", "error", "No base hosts found for project", project_id=project_id, status="failed")
        return None

    root_domains = _extract_project_root_domains(hosts)
    if not root_domains:
        log_event("subfinder", "error", "Unable to extract root domains", project_id=project_id, status="failed")
        return None

    if not subfinder_available():
        log.warning("Subfinder binary not found. Checked PATH and /usr/local/bin/subfinder")
        log_event("subfinder", "error", "Subfinder binary not found", project_id=project_id, status="failed")

    log.info("Subfinder starting for '%s' — root domains: %s", project["name"], ", ".join(root_domains))
    log_event(
        "subfinder",
        "info",
        "Subfinder started",
        project_id=project_id,
        root_domains=root_domains,
        status="running",
    )

    job_id = subfinder_job_create(project_id, ",".join(root_domains), triggered_by)

    with _sf_lock:
        _sf_state[project_id] = {"status": "running", "job_id": job_id, "new_count": 0}

    try:
        raw_records = []
        discovered_all: List[str] = []
        raw_ids = {
            root_domain: subfinder_raw_result_add(
                job_id=job_id,
                project_id=project_id,
                root_domain=root_domain,
                command=" ".join(_build_subfinder_cmd("subfinder", root_domain)),
            )
            for root_domain in root_domains
        }
        workers = max(1, min(8, len(root_domains)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_run_subfinder_for_root, root_domain): root_domain for root_domain in root_domains}
            for future in as_completed(futures):
                root_domain = futures[future]
                run = future.result()
                raw_records.append(
                    {
                        "root_domain": run["root_domain"],
                        "command": run["command"],
                        "status": run["status"],
                        "exit_code": run["exit_code"],
                        "found_count": len(run["found"]),
                    }
                )
                discovered_all.extend(run["found"])
                subfinder_raw_result_finish(
                    raw_ids[root_domain],
                    run["status"],
                    run["exit_code"],
                    len(run["found"]),
                    run["stdout"],
                    run["stderr"],
                )
                if run["status"] != "done":
                    log.warning(
                        "Subfinder run for root=%s finished with status=%s stderr=%s",
                        root_domain,
                        run["status"],
                        (run["stderr"] or "").strip()[:500],
                    )
                elif len(run["found"]) == 0:
                    log.warning("Subfinder returned 0 results — check sources/config (root=%s)", root_domain)

        discovered = sorted(set(discovered_all))
        brute_discovered: Set[str] = set()
        for root_domain in root_domains:
            brute_discovered.update(_bruteforce_dns_hosts(root_domain, discovered + root_domains))
        if brute_discovered:
            log.info("Subfinder brute-force DNS discovered %d additional hosts", len(brute_discovered))
            discovered = sorted(set(discovered) | brute_discovered)
        new_count, new_hosts = subfinder_hosts_add_batch(project_id, discovered)
        subfinder_new_discoveries_add_batch(job_id, project_id, new_hosts)
        httpx_rows = _resolve_active_hosts_with_httpx(new_hosts)
        subfinder_httpx_results_upsert_batch(project_id, job_id, httpx_rows)

        raw_dir = Path("data/subfinder_raw")
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_output_path = raw_dir / f"{job_id}.json.gz"
        with gzip.open(raw_output_path, "wt", encoding="utf-8") as fp:
            json.dump(raw_records, fp, separators=(",", ":"))
        subfinder_job_finish(job_id, new_count, len(discovered), str(raw_output_path))

        if not discovered:
            log.warning("Subfinder returned 0 results — check sources/config")
            log_event("subfinder", "warning", "Subfinder returned 0 results — check sources/config", project_id=project_id, job_id=job_id, status="idle")
            with _sf_lock:
                _sf_state[project_id] = {"status": "done", "job_id": job_id, "new_count": 0}
            return job_id

        with _sf_lock:
            _sf_state[project_id]["new_count"] = new_count
            _sf_state[project_id]["status"] = "ssl_scanning"

        log.info("Subfinder: %d new hosts for '%s', triggering SSL scan",
                 new_count, project["name"])
        log_event("subfinder", "info", f"Discovered {new_count} new hosts", project_id=project_id, job_id=job_id, status="running")

        # SSL scan all discovered hosts from this run so recurring certificate
        # issues are checked and surfaced on every subfinder cycle.
        if discovered:
            _ssl_scan_subfinder_hosts(project_id, discovered, job_id)

        with _sf_lock:
            _sf_state[project_id]["status"] = "done"
        log_event("subfinder", "info", "Subfinder workflow completed", project_id=project_id, job_id=job_id, status="idle")

        return job_id

    except Exception as e:
        log.exception("Subfinder pipeline error for '%s': %s", project["name"], e)
        subfinder_job_error(job_id, str(e))
        log_event("subfinder", "error", f"Subfinder pipeline failed: {e}", project_id=project_id, job_id=job_id, status="failed")
        with _sf_lock:
            if project_id in _sf_state:
                _sf_state[project_id]["status"] = "error"
        return None


def _ssl_scan_subfinder_hosts(project_id: str, hostnames: List[str], job_id: str):
    """Run SSL checks on newly discovered subfinder hosts and save results."""
    from db.database import (
        scan_create, scan_finish, results_batch_save,
        subfinder_hosts_mark_scanned, alert_add, scan_progress,
        alerts_unseen_count, alerts_unsent, alert_mark_sent, alert_settings_get, project_get
    )
    from core.ssl_checker import run_checker
    from scheduler.runner import BATCH_SIZE, PROGRESS_UPDATE_EVERY, _scan_lock, _scan_state
    from core.observability import publish
    from alerts.notifiers import AlertManager

    if not hostnames:
        return

    total = len(hostnames)
    scan = scan_create(project_id, total, by=f"subfinder:{job_id}")
    scan_id = scan["id"]

    with _scan_lock:
        _scan_state[scan_id] = {
            "status": "running", "progress": 0, "total": total,
            "project_id": project_id, "project_name": f"subfinder-{project_id[:8]}",
            "started_at": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc).isoformat()
        }

    result_batch = []
    done_count = [0]
    lock = threading.Lock()
    scanned_hosts = []

    def on_result(done, total_inner, r):
        hostname = r.get("hostname", "")
        scanned_hosts.append(hostname)

        if r.get("is_mismatch") and not r.get("error"):
            mismatch_scope = "same_domain" if r.get("same_base") else "different_domain"
            alert_add(project_id, hostname, "SSL Mismatch",
                      f"[Subfinder] CN '{r.get('cn','?')}' ≠ hostname", scan_id, mismatch_scope=mismatch_scope)
        elif r.get("is_expired") and not r.get("error"):
            alert_add(project_id, hostname, "Expired",
                      f"[Subfinder] Expired {r.get('expiry','?')}", scan_id)
        elif r.get("is_expiring_soon") and not r.get("error"):
            alert_add(project_id, hostname, "Expiring Soon",
                      f"[Subfinder] Expires {r.get('expiry','?')} ({r.get('days_left')}d)", scan_id)

        with lock:
            result_batch.append(r)
            done_count[0] += 1
            if len(result_batch) >= BATCH_SIZE:
                batch = result_batch[:]
                result_batch.clear()
                results_batch_save(scan_id, project_id, batch)
            if done_count[0] % PROGRESS_UPDATE_EVERY == 0:
                scan_progress(scan_id, done_count[0])
                with _scan_lock:
                    if scan_id in _scan_state:
                        _scan_state[scan_id]["progress"] = done_count[0]

    run_checker(hostnames, max_workers=200, progress_callback=on_result)

    with lock:
        if result_batch:
            results_batch_save(scan_id, project_id, result_batch)

    scan_finish(scan_id)
    subfinder_hosts_mark_scanned(project_id, scanned_hosts)
    publish("alert_update", {"unseen_count": alerts_unseen_count()})

    unsent = [a for a in alerts_unsent() if a["project_id"] == project_id]
    if unsent:
        project = project_get(project_id) or {}
        settings = alert_settings_get()
        delivered = AlertManager(settings).dispatch(project.get("name", "Unknown Project"), unsent)
        if delivered:
            for a in unsent:
                alert_mark_sent(a["id"])

    with _scan_lock:
        if scan_id in _scan_state:
            _scan_state[scan_id]["status"] = "done"
            _scan_state[scan_id]["progress"] = total


def run_subfinder_async(project_id: str, triggered_by: str = "manual") -> bool:
    """Start subfinder pipeline in background thread. Returns False if already running."""
    with _sf_lock:
        if _sf_state.get(project_id, {}).get("status") in ("running", "ssl_scanning"):
            return False

    t = threading.Thread(
        target=run_subfinder_for_project,
        args=(project_id, triggered_by),
        daemon=True,
        name=f"sf-{project_id[:8]}"
    )
    t.start()
    return True


def get_sf_state(project_id: str) -> dict:
    with _sf_lock:
        return _sf_state.get(project_id, {}).copy()


# ── Subfinder Scheduler ───────────────────────────────────────────────────────

class SubfinderScheduler:
    def __init__(self):
        self._thread = None
        self._stop = threading.Event()
        self._last_run = {}

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="sf-scheduler")
        self._thread.start()
        log.info("Subfinder scheduler started (binary %s)",
                 "found" if subfinder_available() else "NOT FOUND — install subfinder")

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as e:
                log.exception("Subfinder scheduler error: %s", e)
            self._stop.wait(60)

    def _tick(self):
        from db.database import project_list
        now_ts = time.time()
        for p in project_list():
            if not p.get("enabled") or not p.get("subfinder_enabled"):
                continue
            pid = p["id"]
            interval_min = max(10, min(30, int(p.get("subfinder_interval_minutes", 30) or 30)))
            interval_s = interval_min * 60
            if now_ts - self._last_run.get(pid, 0) >= interval_s:
                self._last_run[pid] = now_ts
                run_subfinder_async(pid, triggered_by="scheduler")


_sf_scheduler = SubfinderScheduler()


def start_subfinder_scheduler():
    _sf_scheduler.start()

def stop_subfinder_scheduler():
    _sf_scheduler.stop()
