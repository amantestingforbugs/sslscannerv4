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
import itertools
import json
import logging
import os
import re
import shlex
import socket
import ssl
import shutil
import subprocess
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set
from urllib.parse import quote_plus, urlparse
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
from core.observability import log_event
from core.target_policy import is_target_allowed, registered_domain

log = logging.getLogger(__name__)

SUBFINDER_BIN = shutil.which("subfinder") or "/usr/local/bin/subfinder"
_sf_lock = threading.Lock()
_sf_state = {}  # project_id -> {status, job_id, new_count}
_subfinder_flag_support: Dict[str, bool] = {}



def _env_int(name: str, default: int, minimum: int = 0, maximum: Optional[int] = None) -> int:
    try:
        value = int(os.getenv(name, str(default)) or default)
    except (TypeError, ValueError):
        value = default
    value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _cancel_pending_futures(futures: Iterable[object]) -> None:
    for future in futures:
        try:
            future.cancel()
        except Exception:
            pass


def _iter_completed_with_deadline(future_map: Dict[object, object], timeout: int, phase_name: str):
    """Yield completed futures until a phase deadline, then cancel pending work.

    This deliberately avoids ``as_completed(..., timeout=...)`` inside a
    ThreadPoolExecutor context manager because the context manager waits for
    still-running futures during shutdown. A single wedged resolver, HTTP
    source, or external tool should not keep the whole subdomain scan running
    forever.
    """
    pending = set(future_map)
    deadline = time.monotonic() + max(1, timeout)
    while pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        done, pending = wait(pending, timeout=remaining, return_when=FIRST_COMPLETED)
        if not done:
            break
        for future in done:
            yield future, future_map[future], False
    if pending:
        log.warning(
            "%s phase timed out after %ss; cancelling %d pending task(s)",
            phase_name,
            timeout,
            len(pending),
        )
        _cancel_pending_futures(pending)
        for future in pending:
            yield future, future_map[future], True


def _compact_raw_record(record: Dict[str, object], sample_size: int = 50) -> Dict[str, object]:
    found = list(record.get("found") or [])
    compact = {k: v for k, v in record.items() if k not in {"found", "stdout", "stderr"}}
    compact["found_count"] = int(record.get("found_count") or len(found) or 0)
    if sample_size > 0 and found:
        compact["found_sample"] = found[:sample_size]
    stderr = str(record.get("stderr") or "")
    if stderr:
        compact["stderr_preview"] = stderr[:1000]
    return compact

def _resolve_subfinder_bin() -> Optional[str]:
    path = shutil.which("subfinder")
    if path:
        return path
    fallback = "/usr/local/bin/subfinder"
    return fallback if Path(fallback).exists() else None


def subfinder_available() -> bool:
    return bool(_resolve_subfinder_bin())


def _subfinder_supports_flag(subfinder_bin: str, flag: str) -> bool:
    """Detect whether the installed subfinder binary supports a specific CLI flag."""
    key = flag.strip().lower()
    if key in _subfinder_flag_support:
        return _subfinder_flag_support[key]
    try:
        help_result = subprocess.run(
            [subfinder_bin, "-h"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        help_text = f"{help_result.stdout}\n{help_result.stderr}".lower()
        _subfinder_flag_support[key] = key in help_text
    except Exception:
        # Be permissive on detection failure: prefer baseline command without optional flags.
        _subfinder_flag_support[key] = False
    return _subfinder_flag_support[key]


def _build_subfinder_cmd(subfinder_bin: str, root_domain: str) -> List[str]:
    cmd = [subfinder_bin, "-d", root_domain, "-silent", "-timeout", "30"]

    # Aggressive defaults to maximize enumeration yield where supported.
    preferred_flags = ["-all", "-recursive"]

    # Optional env override to add additional flags without code changes. Keep
    # value tokens that belong to supported flags (for example: "-rate-limit 50").
    extra_tokens = shlex.split(os.getenv("SUBFINDER_EXTRA_FLAGS", "").strip())

    # Optional config/provider files improve coverage when users configure API keys/sources.
    cfg = os.getenv("SUBFINDER_CONFIG", "").strip()
    if cfg and Path(cfg).exists() and _subfinder_supports_flag(subfinder_bin, "-config"):
        cmd.extend(["-config", cfg])
    pconf = os.getenv("SUBFINDER_PROVIDER_CONFIG", "").strip()
    if pconf and Path(pconf).exists() and _subfinder_supports_flag(subfinder_bin, "-pc"):
        cmd.extend(["-pc", pconf])

    for flag in preferred_flags:
        if flag not in cmd and _subfinder_supports_flag(subfinder_bin, flag):
            cmd.append(flag)

    idx = 0
    while idx < len(extra_tokens):
        token = extra_tokens[idx]
        idx += 1
        if not token.startswith("-") or token in cmd:
            continue
        if not _subfinder_supports_flag(subfinder_bin, token):
            # Skip a value token following an unsupported option.
            if idx < len(extra_tokens) and not extra_tokens[idx].startswith("-"):
                idx += 1
            continue
        cmd.append(token)
        if idx < len(extra_tokens) and not extra_tokens[idx].startswith("-"):
            cmd.append(extra_tokens[idx])
            idx += 1

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
_DEFAULT_BRUTE_LABELS = (
    # A compact built-in "top subdomains" list used before any custom files/URLs.
    # Operators can extend/replace this with DNS_BRUTEFORCE_LABELS,
    # DNS_BRUTEFORCE_WORDLIST_FILES, or DNS_BRUTEFORCE_WORDLIST_URLS.
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2",
    "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog", "pop3",
    "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new", "mysql",
    "old", "lists", "support", "mobile", "mx", "static", "docs", "beta", "shop", "sql",
    "secure", "demo", "cp", "calendar", "wiki", "web", "media", "email", "images", "img",
    "www1", "intranet", "portal", "video", "sip", "dns2", "api", "cdn", "stats", "dns1",
    "ns4", "www3", "dns", "search", "staging", "server", "mx1", "chat", "wap", "my",
    "svn", "mail1", "sites", "proxy", "ads", "host", "crm", "cms", "backup", "mx2",
    "lyncdiscover", "info", "apps", "download", "remote", "db", "forums", "store", "relay", "files",
    "newsletter", "app", "live", "owa", "en", "start", "sms", "office", "exchange", "ipv4",
    "mail3", "help", "blogs", "helpdesk", "web1", "home", "library", "ftp2", "ntp", "monitor",
    "login", "service", "correo", "www4", "mssql", "dev2", "stage", "gw", "jobs", "cloud",
    "download2", "ldap", "archive", "payment", "payments", "auth", "sso", "idp", "vpn2", "git",
    "gitlab", "jenkins", "ci", "build", "registry", "docker", "k8s", "kubernetes", "grafana", "prometheus",
    "status", "assets", "edge", "gateway", "gw1", "gw2", "uat", "qa", "preprod", "prod",
    "internal", "external", "partners", "partner", "client", "clients", "customer", "customers", "account", "accounts",
    "billing", "invoice", "invoices", "pay", "checkout", "cart", "orders", "order", "tracking", "track",
    "api1", "api2", "api3", "dev-api", "staging-api", "test-api", "admin-api", "mobile-api", "graphql", "rest",
    "v1", "v2", "v3", "legacy", "old-api", "new-api", "sandbox", "lab", "labs", "research",
    "web2", "web3", "web4", "node1", "node2", "node3", "app1", "app2", "app3", "db1",
    "db2", "db3", "cache", "redis", "memcached", "queue", "rabbitmq", "kafka", "elastic", "elasticsearch",
    "solr", "splunk", "kibana", "log", "logs", "logging", "metrics", "monitoring", "alerts", "alert",
    "noc", "ops", "sec", "security", "waf", "firewall", "fw", "fw1", "fw2", "bastion",
    "jump", "jumpbox", "rdp", "ssh", "sftp", "vpn1", "openvpn", "wireguard", "citrix", "remote2",
    "adfs", "ldap1", "dc", "dc1", "dc2", "ad", "radius", "kerberos", "ntp1", "time",
    "voip", "pbx", "sip1", "lync", "teams", "meet", "meeting", "conference", "call", "calls",
    "img1", "img2", "static1", "static2", "cdn1", "cdn2", "media1", "media2", "uploads", "upload",
    "download1", "downloads", "file", "files1", "assets1", "asset", "content", "content1", "origin", "origin1",
    "www5", "www6", "www7", "mail4", "mail5", "mx3", "mx4", "smtp1", "smtp2", "imap1",
    "pop1", "ns5", "ns6", "dns3", "dns4", "host1", "host2", "server1", "server2", "test1",
    "test2", "dev1", "stage1", "stage2", "qa1", "qa2", "uat1", "uat2", "preprod1", "prod1",
)


def _dns_bruteforce_enabled() -> bool:
    return os.getenv("DNS_BRUTEFORCE_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}


def _dedupe_labels(labels: Iterable[str], limit: int = 0) -> List[str]:
    cleaned: List[str] = []
    seen: Set[str] = set()
    for raw in labels:
        label = (raw or "").strip().lower().strip(".")
        if not label or "." in label or not re.fullmatch(r"[a-z0-9-]{1,63}", label):
            continue
        if label in seen:
            continue
        cleaned.append(label)
        seen.add(label)
        if limit > 0 and len(cleaned) >= limit:
            break
    return cleaned


def _numbered_brute_labels() -> List[str]:
    """Generate common numbered labels so the built-in list reaches top-N depth."""
    bases = (
        "www", "api", "app", "web", "mail", "smtp", "mx", "ns", "dns", "dev", "test", "stage",
        "staging", "qa", "uat", "prod", "vpn", "portal", "admin", "cdn", "static", "img",
        "db", "server", "host", "node", "gw", "proxy", "cache", "login", "auth", "sso",
    )
    return [f"{base}{num}" for base, num in itertools.product(bases, range(1, 31))]


def _labels_from_wordlist_file(path: str, limit: int) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fp:
            return _dedupe_labels((line.split("#", 1)[0] for line in fp), limit=limit)
    except Exception as e:
        log.warning("Unable to read DNS brute-force wordlist file %s: %s", path, e)
        return []


def _labels_from_wordlist_url(url: str, limit: int, timeout: int = 30) -> List[str]:
    try:
        req = Request(url, headers={"User-Agent": "ssl-sentinel/1.0"})
        ctx = ssl.create_default_context()
        with urlopen(req, timeout=timeout, context=ctx) as res:
            body = res.read(2_000_000).decode("utf-8", errors="replace")
        return _dedupe_labels((line.split("#", 1)[0] for line in body.splitlines()), limit=limit)
    except Exception as e:
        log.warning("Unable to fetch DNS brute-force wordlist URL %s: %s", url, e)
        return []


def _brute_labels() -> List[str]:
    top_n = _env_int("DNS_BRUTEFORCE_TOP_N", 1000, minimum=1, maximum=1_000_000)
    raw = os.getenv("DNS_BRUTEFORCE_LABELS", "")
    custom = _dedupe_labels(raw.split(","), limit=top_n)
    if custom:
        return custom

    labels: List[str] = []
    labels.extend(_DEFAULT_BRUTE_LABELS)
    labels.extend(_numbered_brute_labels())

    remaining = max(0, top_n - len(_dedupe_labels(labels)))
    for file_path in [x.strip() for x in os.getenv("DNS_BRUTEFORCE_WORDLIST_FILES", "").split(",") if x.strip()]:
        if remaining <= 0:
            break
        labels.extend(_labels_from_wordlist_file(file_path, remaining))
        remaining = max(0, top_n - len(_dedupe_labels(labels)))

    for url in [x.strip() for x in os.getenv("DNS_BRUTEFORCE_WORDLIST_URLS", "").split(",") if x.strip()]:
        if remaining <= 0:
            break
        labels.extend(_labels_from_wordlist_url(url, remaining))
        remaining = max(0, top_n - len(_dedupe_labels(labels)))

    return _dedupe_labels(labels, limit=top_n)


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
    root = registered_domain(host)
    return root or None


def _extract_project_root_domains(hosts: List[str]) -> List[str]:
    """Extract registrable root domains from a project host list."""
    normalized: List[str] = []
    for raw in hosts:
        raw_line = (raw or "").strip()
        if not raw_line:
            continue
        for token in re.split(r"[\s,;]+", raw_line):
            h = _normalize_host(token)
            if not h or "." not in h or not _HOST_RE.match(h) or not is_target_allowed(h):
                continue
            normalized.append(h)

    if not normalized:
        return []

    roots: Set[str] = set()
    for h in normalized:
        root = _registrable_domain(h)
        if root and is_target_allowed(root):
            roots.add(root)

    return sorted(roots)


def _is_host_within_root(host: str, root_domain: str) -> bool:
    if not is_target_allowed(host):
        return False
    if host == root_domain:
        return True
    return host.endswith(f".{root_domain}")


def _resolve_host_ips(host: str, timeout: float = 1.5) -> Set[str]:
    """Resolve a host to IP strings without mutating process-wide socket defaults."""

    def _resolve() -> Set[str]:
        return {str(row[4][0]) for row in socket.getaddrinfo(host, None) if row and row[4]}

    with ThreadPoolExecutor(max_workers=1) as resolver:
        future = resolver.submit(_resolve)
        try:
            return future.result(timeout=timeout)
        except Exception:
            return set()


def _host_resolves(host: str, timeout: float = 1.5) -> bool:
    return bool(_resolve_host_ips(host, timeout=timeout))


def _wildcard_dns_ips(root_domain: str) -> Set[str]:
    labels = ("ssl-sentinel-nohit-a", "ssl-sentinel-nohit-b")
    ips: Set[str] = set()
    for label in labels:
        ips.update(_resolve_host_ips(f"{label}-{int(time.time())}.{root_domain}"))
    return ips


def _host_suffixes_under_root(host: str, root_domain: str, max_depth: int = 0) -> List[str]:
    """Return every in-scope sub-zone from deepest to shallowest.

    For ``api.dev.example.com`` this yields ``api.dev.example.com`` and
    ``dev.example.com``.  Brute-force and permutation stages prepend labels to
    each suffix so scans continue below already discovered multi-level hosts
    instead of stopping at one nested label.
    """
    if not _is_host_within_root(host, root_domain) or host == root_domain:
        return []
    left = host[:-len(root_domain)].rstrip(".")
    labels = [part for part in left.split(".") if part]
    suffixes: List[str] = []
    for idx in range(len(labels)):
        suffix = ".".join(labels[idx:] + [root_domain])
        if suffix != root_domain and _HOST_RE.match(suffix):
            suffixes.append(suffix)
        if max_depth > 0 and len(suffixes) >= max_depth:
            break
    return suffixes


def _generate_bruteforce_candidates(root_domain: str, seed_hosts: List[str]) -> Set[str]:
    labels = _brute_labels()
    candidates: Set[str] = {f"{label}.{root_domain}" for label in labels}
    deep_suffix_limit = _env_int("DNS_BRUTEFORCE_SUFFIXES_PER_HOST", 5, minimum=1, maximum=25)
    relevant = [h for h in seed_hosts if _is_host_within_root(h, root_domain)]
    for host in relevant:
        for suffix in _host_suffixes_under_root(host, root_domain, max_depth=deep_suffix_limit):
            for label in labels:
                candidates.add(f"{label}.{suffix}")
    return {c for c in candidates if _HOST_RE.match(c)}


def _ordered_bruteforce_candidates(root_domain: str, seed_hosts: List[str]) -> List[str]:
    labels = _brute_labels()
    ordered: List[str] = [f"{label}.{root_domain}" for label in labels]
    deep_suffix_limit = _env_int("DNS_BRUTEFORCE_SUFFIXES_PER_HOST", 5, minimum=1, maximum=25)
    relevant = [h for h in seed_hosts if _is_host_within_root(h, root_domain)]
    for host in sorted(relevant):
        for suffix in _host_suffixes_under_root(host, root_domain, max_depth=deep_suffix_limit):
            ordered.extend(f"{label}.{suffix}" for label in labels)
    deduped: List[str] = []
    seen: Set[str] = set()
    for candidate in ordered:
        if candidate in seen or not _HOST_RE.match(candidate):
            continue
        deduped.append(candidate)
        seen.add(candidate)
    return deduped


def _bruteforce_dns_hosts(root_domain: str, seed_hosts: List[str], max_candidates: int = 0) -> List[str]:
    if max_candidates <= 0:
        max_candidates = _env_int("DNS_BRUTEFORCE_MAX_CANDIDATES", 5000, minimum=1, maximum=1_000_000)
    candidates = _ordered_bruteforce_candidates(root_domain, seed_hosts)
    if max_candidates > 0:
        candidates = candidates[:max_candidates]
    resolved: List[str] = []
    wildcard_ips = set()
    keep_wildcards = os.getenv("DNS_BRUTEFORCE_KEEP_WILDCARD", "0").strip().lower() in {"1", "true", "yes", "on"}
    if not keep_wildcards:
        wildcard_ips = _wildcard_dns_ips(root_domain)
    workers = max(8, min(128, len(candidates) or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_resolve_host_ips, host): host for host in candidates}
        for future in as_completed(futures):
            host = futures[future]
            try:
                ips = set(future.result() or [])
                if ips and (keep_wildcards or not wildcard_ips or not ips.issubset(wildcard_ips)):
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


def _run_assetfinder_for_root(root_domain: str, timeout: int = 180) -> List[str]:
    assetfinder_bin = shutil.which("assetfinder") or "/usr/local/bin/assetfinder"
    if not assetfinder_bin or not Path(assetfinder_bin).exists():
        return []
    try:
        run = subprocess.run(
            [assetfinder_bin, "--subs-only", root_domain],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if run.returncode not in (0, 1):
            return []
        found = {
            candidate
            for ln in (run.stdout or "").splitlines()
            for candidate in [_normalize_host(ln)]
            if candidate and _HOST_RE.match(candidate) and _is_host_within_root(candidate, root_domain)
        }
        return sorted(found)
    except Exception:
        return []


def _run_amass_passive_for_root(root_domain: str, timeout: int = 240) -> List[str]:
    amass_bin = shutil.which("amass") or "/usr/local/bin/amass"
    if not amass_bin or not Path(amass_bin).exists():
        return []
    try:
        run = subprocess.run(
            [amass_bin, "enum", "-passive", "-nocolor", "-d", root_domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if run.returncode not in (0, 1):
            return []
        found = {
            candidate
            for ln in (run.stdout or "").splitlines()
            for candidate in [_normalize_host(ln)]
            if candidate and _HOST_RE.match(candidate) and _is_host_within_root(candidate, root_domain)
        }
        return sorted(found)
    except Exception:
        return []


def _run_findomain_for_root(root_domain: str, timeout: int = 240) -> List[str]:
    findomain_bin = shutil.which("findomain") or "/usr/local/bin/findomain"
    if not findomain_bin or not Path(findomain_bin).exists():
        return []
    try:
        run = subprocess.run(
            [findomain_bin, "-t", root_domain, "-q"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if run.returncode not in (0, 1):
            return []
        return _filter_hosts_for_root(run.stdout.splitlines(), root_domain)
    except Exception:
        return []


def _filter_hosts_for_root(candidates: Iterable[str], root_domain: str) -> List[str]:
    found = {
        host
        for token in candidates
        for host in [_normalize_host(str(token or ""))]
        if host and _HOST_RE.match(host) and _is_host_within_root(host, root_domain)
    }
    return sorted(found)


def _query_crtsh_for_root(root_domain: str, timeout: int = 45) -> List[str]:
    url = f"https://crt.sh/?q=%25.{root_domain}&output=json"
    try:
        req = Request(url, headers={"User-Agent": "ssl-sentinel/1.0"})
        ctx = ssl.create_default_context()
        with urlopen(req, timeout=timeout, context=ctx) as res:
            body = res.read().decode("utf-8", errors="replace")
        rows = json.loads(body or "[]")
        found: Set[str] = set()
        for row in rows:
            names = str(row.get("name_value") or "").splitlines()
            for name in names:
                host = _normalize_host(name)
                if host and _HOST_RE.match(host) and _is_host_within_root(host, root_domain):
                    found.add(host)
        return sorted(found)
    except Exception:
        return []


def _query_bufferover_for_root(root_domain: str, timeout: int = 30) -> List[str]:
    url = f"https://dns.bufferover.run/dns?q=.{root_domain}"
    try:
        req = Request(url, headers={"User-Agent": "ssl-sentinel/1.0"})
        ctx = ssl.create_default_context()
        with urlopen(req, timeout=timeout, context=ctx) as res:
            body = res.read().decode("utf-8", errors="replace")
        payload = json.loads(body or "{}")
        found: Set[str] = set()
        for key in ("FDNS_A", "RDNS"):
            for row in payload.get(key) or []:
                token = (row or "").split(",")[-1].strip()
                host = _normalize_host(token)
                if host and _HOST_RE.match(host) and _is_host_within_root(host, root_domain):
                    found.add(host)
        return sorted(found)
    except Exception:
        return []


def _query_rapiddns_for_root(root_domain: str, timeout: int = 30) -> List[str]:
    url = f"https://rapiddns.io/subdomain/{root_domain}?full=1"
    try:
        req = Request(url, headers={"User-Agent": "ssl-sentinel/1.0"})
        ctx = ssl.create_default_context()
        with urlopen(req, timeout=timeout, context=ctx) as res:
            body = res.read().decode("utf-8", errors="replace")
        found: Set[str] = set()
        # rapiddns contains many HTML anchors and table cells with hostnames
        for match in re.findall(r"([a-zA-Z0-9][a-zA-Z0-9.-]*\.%s)" % re.escape(root_domain), body):
            host = _normalize_host(match)
            if host and _HOST_RE.match(host) and _is_host_within_root(host, root_domain):
                found.add(host)
        return sorted(found)
    except Exception:
        return []


def _http_text_with_retries(
    url: str,
    timeout: int = 30,
    retries: int = 3,
    backoff: float = 1.4,
    headers: Optional[Dict[str, str]] = None,
    max_bytes: int = 5_000_000,
) -> str:
    """Fetch text endpoint with lightweight retries/jitter for unstable OSINT APIs."""
    last_err = None
    for attempt in range(1, max(1, retries) + 1):
        try:
            req_headers = {"User-Agent": "ssl-sentinel/1.0"}
            if headers:
                req_headers.update(headers)
            req = Request(url, headers=req_headers)
            ctx = ssl.create_default_context()
            with urlopen(req, timeout=timeout, context=ctx) as res:
                return res.read(max_bytes).decode("utf-8", errors="replace")
        except (HTTPError, URLError, TimeoutError, ssl.SSLError) as e:
            last_err = e
            if attempt < retries:
                sleep_for = (backoff ** attempt) + (attempt * 0.13)
                time.sleep(min(4.0, sleep_for))
        except Exception as e:
            last_err = e
            break
    raise RuntimeError(f"request failed for {url}: {last_err}")


def _http_json_with_retries(
    url: str,
    timeout: int = 30,
    retries: int = 3,
    backoff: float = 1.4,
    headers: Optional[Dict[str, str]] = None,
) -> object:
    """Fetch JSON endpoint with lightweight retries/jitter for unstable OSINT APIs."""
    body = _http_text_with_retries(url, timeout=timeout, retries=retries, backoff=backoff, headers=headers)
    return json.loads(body or "{}")


def _query_hackertarget_for_root(root_domain: str, timeout: int = 35) -> List[str]:
    """Pull hostsearch data from HackerTarget public API."""
    url = f"https://api.hackertarget.com/hostsearch/?q={root_domain}"
    try:
        req = Request(url, headers={"User-Agent": "ssl-sentinel/1.0"})
        ctx = ssl.create_default_context()
        with urlopen(req, timeout=timeout, context=ctx) as res:
            body = res.read().decode("utf-8", errors="replace")
        found: Set[str] = set()
        for ln in body.splitlines():
            token = (ln or "").split(",", 1)[0].strip()
            host = _normalize_host(token)
            if host and _HOST_RE.match(host) and _is_host_within_root(host, root_domain):
                found.add(host)
        return sorted(found)
    except Exception:
        return []


def _query_anubis_for_root(root_domain: str, timeout: int = 35) -> List[str]:
    """Pull public subdomain lists from the jldc/anubis endpoint."""
    url = f"https://jldc.me/anubis/subdomains/{root_domain}"
    try:
        rows = _http_json_with_retries(url, timeout=timeout, retries=2)
        return _filter_hosts_for_root(rows if isinstance(rows, list) else [], root_domain)
    except Exception:
        return []


def _query_subdomain_center_for_root(root_domain: str, timeout: int = 35) -> List[str]:
    """Pull public hostnames from Subdomain Center."""
    url = f"https://api.subdomain.center/?domain={root_domain}"
    try:
        rows = _http_json_with_retries(url, timeout=timeout, retries=2)
        return _filter_hosts_for_root(rows if isinstance(rows, list) else [], root_domain)
    except Exception:
        return []


def _query_shodan_for_root(root_domain: str, timeout: int = 35) -> List[str]:
    """Pull subdomains from Shodan DNS Domain API when SHODAN_API_KEY is configured."""
    api_key = os.getenv("SHODAN_API_KEY", "").strip()
    if not api_key:
        return []
    url = f"https://api.shodan.io/dns/domain/{root_domain}?key={api_key}"
    try:
        payload = _http_json_with_retries(url, timeout=timeout, retries=2)
        found: Set[str] = set()
        for sub in (payload or {}).get("subdomains") or []:
            host = _normalize_host(f"{sub}.{root_domain}")
            if host and _HOST_RE.match(host) and _is_host_within_root(host, root_domain):
                found.add(host)
        for row in (payload or {}).get("data") or []:
            token = str((row or {}).get("subdomain") or "").strip()
            host = _normalize_host(token)
            if host and "." not in host:
                host = _normalize_host(f"{host}.{root_domain}")
            if host and _HOST_RE.match(host) and _is_host_within_root(host, root_domain):
                found.add(host)
        return sorted(found)
    except Exception:
        return []


def _query_chaos_for_root(root_domain: str, timeout: int = 35) -> List[str]:
    """Pull subdomains from ProjectDiscovery Chaos when CHAOS_API_KEY is configured."""
    api_key = os.getenv("CHAOS_API_KEY", "").strip()
    if not api_key:
        return []
    url = f"https://dns.projectdiscovery.io/dns/{root_domain}/subdomains"
    try:
        req = Request(url, headers={"User-Agent": "ssl-sentinel/1.0", "Authorization": api_key})
        ctx = ssl.create_default_context()
        with urlopen(req, timeout=timeout, context=ctx) as res:
            body = res.read().decode("utf-8", errors="replace")
        payload = json.loads(body or "{}")
        candidates = []
        for token in (payload or {}).get("subdomains") or []:
            token = str(token or "").strip()
            candidates.append(token if token.endswith(f".{root_domain}") else f"{token}.{root_domain}")
        return _filter_hosts_for_root(candidates, root_domain)
    except Exception:
        return []


def _query_virustotal_for_root(root_domain: str, timeout: int = 35) -> List[str]:
    """Pull subdomains from VirusTotal when VT API key is configured."""
    api_key = os.getenv("VT_API_KEY", "").strip()
    if not api_key:
        return []
    url = f"https://www.virustotal.com/api/v3/domains/{root_domain}/subdomains?limit=1000"
    try:
        req = Request(url, headers={"User-Agent": "ssl-sentinel/1.0", "x-apikey": api_key})
        ctx = ssl.create_default_context()
        with urlopen(req, timeout=timeout, context=ctx) as res:
            body = res.read().decode("utf-8", errors="replace")
        payload = json.loads(body or "{}")
        found: Set[str] = set()
        for row in (payload or {}).get("data") or []:
            host = _normalize_host(str((row or {}).get("id") or ""))
            if host and _HOST_RE.match(host) and _is_host_within_root(host, root_domain):
                found.add(host)
        return sorted(found)
    except Exception:
        return []


def _query_securitytrails_for_root(root_domain: str, timeout: int = 35) -> List[str]:
    """Pull subdomains from SecurityTrails when API key is configured."""
    api_key = os.getenv("SECURITYTRAILS_API_KEY", "").strip()
    if not api_key:
        return []
    url = f"https://api.securitytrails.com/v1/domain/{root_domain}/subdomains"
    try:
        req = Request(url, headers={"User-Agent": "ssl-sentinel/1.0", "apikey": api_key})
        ctx = ssl.create_default_context()
        with urlopen(req, timeout=timeout, context=ctx) as res:
            body = res.read().decode("utf-8", errors="replace")
        payload = json.loads(body or "{}")
        found: Set[str] = set()
        for left in (payload or {}).get("subdomains") or []:
            host = _normalize_host(f"{left}.{root_domain}")
            if host and _HOST_RE.match(host) and _is_host_within_root(host, root_domain):
                found.add(host)
        return sorted(found)
    except Exception:
        return []


def _query_certspotter_for_root(root_domain: str, timeout: int = 40) -> List[str]:
    """Pull certificate transparency names from Cert Spotter API."""
    url = f"https://api.certspotter.com/v1/issuances?domain={root_domain}&include_subdomains=true&expand=dns_names"
    try:
        rows = _http_json_with_retries(url, timeout=timeout, retries=3)
        found: Set[str] = set()
        for row in rows or []:
            for name in row.get("dns_names") or []:
                host = _normalize_host(str(name))
                if host and _HOST_RE.match(host) and _is_host_within_root(host, root_domain):
                    found.add(host)
        return sorted(found)
    except Exception:
        return []


def _query_alienvault_otx_for_root(root_domain: str, timeout: int = 40) -> List[str]:
    """Pull passive DNS hostnames from AlienVault OTX."""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{root_domain}/passive_dns"
    try:
        payload = _http_json_with_retries(url, timeout=timeout, retries=3)
        found: Set[str] = set()
        for row in (payload or {}).get("passive_dns") or []:
            host = _normalize_host(str(row.get("hostname") or row.get("host") or ""))
            if host and _HOST_RE.match(host) and _is_host_within_root(host, root_domain):
                found.add(host)
        return sorted(found)
    except Exception:
        return []


def _query_threatcrowd_for_root(root_domain: str, timeout: int = 35) -> List[str]:
    """Pull historical subdomains from ThreatCrowd."""
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={root_domain}"
    try:
        payload = _http_json_with_retries(url, timeout=timeout, retries=2)
        found: Set[str] = set()
        for token in (payload or {}).get("subdomains") or []:
            host = _normalize_host(str(token))
            if host and _HOST_RE.match(host) and _is_host_within_root(host, root_domain):
                found.add(host)
        return sorted(found)
    except Exception:
        return []


def _query_urlscan_for_root(root_domain: str, timeout: int = 45) -> List[str]:
    """Pull related hostnames from public URLScan search index."""
    url = f"https://urlscan.io/api/v1/search/?q=domain:{root_domain}&size=100"
    try:
        payload = _http_json_with_retries(url, timeout=timeout, retries=3)
        found: Set[str] = set()
        for row in (payload or {}).get("results") or []:
            task = row.get("task") or {}
            page = row.get("page") or {}
            for token in (task.get("domain"), page.get("domain"), page.get("apexDomain")):
                host = _normalize_host(str(token or ""))
                if host and _HOST_RE.match(host) and _is_host_within_root(host, root_domain):
                    found.add(host)
        return sorted(found)
    except Exception:
        return []


def _query_wayback_for_root(root_domain: str, timeout: int = 45) -> List[str]:
    """Harvest hostnames from Internet Archive CDX URLs index."""
    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url=*.{root_domain}/*&output=json&fl=original&collapse=urlkey"
    )
    try:
        rows = _http_json_with_retries(url, timeout=timeout, retries=2)
        found: Set[str] = set()
        for row in rows[1:] if isinstance(rows, list) else []:
            if not row:
                continue
            raw = str(row[0])
            host = _normalize_host(raw)
            if host and _HOST_RE.match(host) and _is_host_within_root(host, root_domain):
                found.add(host)
        return sorted(found)
    except Exception:
        return []

def _query_commoncrawl_for_root(root_domain: str, timeout: int = 40) -> List[str]:
    """Harvest hosts from the most recent Common Crawl URL indexes."""
    try:
        indexes = _http_json_with_retries("https://index.commoncrawl.org/collinfo.json", timeout=timeout, retries=2)
        index_ids = [str(row.get("id") or "") for row in indexes or [] if row.get("id")]
    except Exception:
        index_ids = []
    max_indexes = _env_int("COMMONCRAWL_INDEX_LIMIT", 2, minimum=1, maximum=10)
    found: Set[str] = set()
    for index_id in index_ids[:max_indexes]:
        url = (
            f"https://index.commoncrawl.org/{index_id}-index"
            f"?url=*.{root_domain}/*&output=json&fl=url&collapse=urlkey"
        )
        try:
            body = _http_text_with_retries(url, timeout=timeout, retries=2, max_bytes=8_000_000)
            for line in body.splitlines():
                try:
                    row = json.loads(line)
                    found.update(_extract_hosts_from_text(str(row.get("url") or ""), root_domain))
                except Exception:
                    found.update(_extract_hosts_from_text(line, root_domain))
        except Exception:
            continue
    return sorted(found)


def _query_github_code_for_root(root_domain: str, timeout: int = 40) -> List[str]:
    """Search GitHub code for hostnames when GITHUB_TOKEN is configured."""
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if not token:
        return []
    query = quote_plus(f'".{root_domain}"')
    url = f"https://api.github.com/search/code?q={query}&per_page=100"
    try:
        payload = _http_json_with_retries(
            url,
            timeout=timeout,
            retries=2,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.text-match+json"},
        )
        found: Set[str] = set()
        for item in (payload or {}).get("items") or []:
            found.update(_extract_hosts_from_text(str(item.get("name") or ""), root_domain))
            found.update(_extract_hosts_from_text(str(item.get("path") or ""), root_domain))
            for match in item.get("text_matches") or []:
                found.update(_extract_hosts_from_text(str(match.get("fragment") or ""), root_domain))
        return sorted(found)
    except Exception:
        return []


def _query_dnsdumpster_for_root(root_domain: str, timeout: int = 30) -> List[str]:
    """Parse hosts from an operator-provided DNSDumpster export/mirror URL."""
    export_url = os.getenv("DNSDUMPSTER_EXPORT_URL", "").strip()
    if not export_url:
        return []
    try:
        body = _http_text_with_retries(export_url.format(domain=root_domain), timeout=timeout, retries=2)
        return sorted(_extract_hosts_from_text(body, root_domain))
    except Exception as e:
        log.debug("DNSDumpster export failed for %s: %s", root_domain, e)
        return []

def _extract_hosts_from_text(body: str, root_domain: str) -> Set[str]:
    found: Set[str] = set()
    if not body:
        return found
    pattern = re.compile(rf"\b(?:[a-zA-Z0-9-]+\.)+{re.escape(root_domain)}\b", re.IGNORECASE)
    for match in pattern.findall(body):
        host = _normalize_host(match)
        if host and _HOST_RE.match(host) and _is_host_within_root(host, root_domain):
            found.add(host)
    return found


def _query_common_web_artifacts_for_root(root_domain: str, timeout: int = 25) -> List[str]:
    """Collect subdomains from robots/sitemap/security.txt/crossdomain.xml endpoints."""
    endpoints = (
        f"https://{root_domain}/robots.txt",
        f"https://{root_domain}/sitemap.xml",
        f"https://{root_domain}/.well-known/security.txt",
        f"https://{root_domain}/crossdomain.xml",
        f"http://{root_domain}/robots.txt",
    )
    found: Set[str] = set()
    for url in endpoints:
        try:
            req = Request(url, headers={"User-Agent": "ssl-sentinel/1.0"})
            ctx = ssl.create_default_context()
            with urlopen(req, timeout=timeout, context=ctx) as res:
                if res.status and int(res.status) >= 400:
                    continue
                body = res.read().decode("utf-8", errors="replace")
            found.update(_extract_hosts_from_text(body, root_domain))
        except Exception:
            continue
    return sorted(found)


def _query_tls_san_hosts_for_root(root_domain: str, timeout: int = 8) -> List[str]:
    """Expand subdomains from live TLS certificates SAN list on apex and common web hosts."""
    scan_hosts = (
        root_domain,
        f"www.{root_domain}",
        f"api.{root_domain}",
        f"app.{root_domain}",
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    found: Set[str] = set()
    for target in scan_hosts:
        try:
            with socket.create_connection((target, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as tls:
                    cert = tls.getpeercert()
            for token in cert.get("subjectAltName", []):
                if not isinstance(token, tuple) or len(token) != 2 or token[0] != "DNS":
                    continue
                host = _normalize_host(str(token[1]))
                if host and _HOST_RE.match(host) and _is_host_within_root(host, root_domain):
                    found.add(host)
        except Exception:
            continue
    return sorted(found)


EnumerationSource = Callable[[str], List[str]]


def _passive_enumeration_sources() -> Dict[str, EnumerationSource]:
    """Return every passive/tool source the pipeline knows how to query."""
    return {
        "assetfinder": _run_assetfinder_for_root,
        "amass": _run_amass_passive_for_root,
        "findomain": _run_findomain_for_root,
        "crtsh": _query_crtsh_for_root,
        "bufferover": _query_bufferover_for_root,
        "rapiddns": _query_rapiddns_for_root,
        "anubis": _query_anubis_for_root,
        "subdomain_center": _query_subdomain_center_for_root,
        "hackertarget": _query_hackertarget_for_root,
        "certspotter": _query_certspotter_for_root,
        "wayback": _query_wayback_for_root,
        "commoncrawl": _query_commoncrawl_for_root,
        "github_code": _query_github_code_for_root,
        "dnsdumpster_export": _query_dnsdumpster_for_root,
        "alienvault_otx": _query_alienvault_otx_for_root,
        "threatcrowd": _query_threatcrowd_for_root,
        "urlscan": _query_urlscan_for_root,
        "web_artifacts": _query_common_web_artifacts_for_root,
        "tls_san": _query_tls_san_hosts_for_root,
        "virustotal": _query_virustotal_for_root,
        "securitytrails": _query_securitytrails_for_root,
        "shodan": _query_shodan_for_root,
        "chaos": _query_chaos_for_root,
    }


def _tool_summary() -> str:
    sources = ["subfinder(all-sources)", *_passive_enumeration_sources().keys(), "deep_recursive_passive", "dns_bruteforce", "dns_permutation"]
    return ",".join(sources)


def _run_passive_source(source_name: str, source_fn: EnumerationSource, root_domain: str) -> Dict[str, object]:
    started = time.time()
    try:
        found = _filter_hosts_for_root(source_fn(root_domain) or [], root_domain)
        return {
            "source": source_name,
            "root_domain": root_domain,
            "status": "done",
            "found": found,
            "found_count": len(found),
            "elapsed_ms": int((time.time() - started) * 1000),
            "stderr": "",
        }
    except Exception as e:
        return {
            "source": source_name,
            "root_domain": root_domain,
            "status": "error",
            "found": [],
            "found_count": 0,
            "elapsed_ms": int((time.time() - started) * 1000),
            "stderr": str(e),
        }


def _deep_scan_enabled() -> bool:
    return _env_bool("SUBDOMAIN_DEEP_SCAN_ENABLED", True)


def _configured_deep_sources(all_sources: Dict[str, EnumerationSource]) -> Dict[str, EnumerationSource]:
    """Select passive sources used for recursive sub-zone enumeration."""
    default_names = (
        "crtsh",
        "certspotter",
        "wayback",
        "commoncrawl",
        "urlscan",
        "rapiddns",
        "anubis",
        "subdomain_center",
        "alienvault_otx",
        "bufferover",
    )
    raw = os.getenv("SUBDOMAIN_DEEP_SOURCES", "").strip()
    if raw:
        requested = [item.strip() for item in raw.split(",") if item.strip()]
        if any(item.lower() == "all" for item in requested):
            return dict(all_sources)
        return {name: all_sources[name] for name in requested if name in all_sources}
    return {name: all_sources[name] for name in default_names if name in all_sources}


def _deep_scan_targets(root_domain: str, discovered: List[str], seen_targets: Set[str], limit: int) -> List[str]:
    """Pick the deepest known in-scope zones to recurse into next."""
    candidates: Set[str] = set()
    for host in discovered:
        if not _is_host_within_root(host, root_domain) or host == root_domain:
            continue
        candidates.update(_host_suffixes_under_root(host, root_domain))
    ordered = sorted(
        (target for target in candidates if target not in seen_targets),
        key=lambda host: (-host.count("."), host),
    )
    return ordered[:limit] if limit > 0 else ordered


def _run_recursive_passive_enumeration(
    root_domains: List[str],
    discovered: List[str],
    all_sources: Dict[str, EnumerationSource],
) -> Dict[str, object]:
    """Recursively query passive sources against discovered sub-zones.

    Most public sources support querying any DNS zone, not just the apex. Running
    them again for zones like ``dev.example.com`` is what exposes deeper names
    such as ``api.internal.dev.example.com``. Limits and phase timeouts keep this
    aggressive mode bounded for large projects.
    """
    if not _deep_scan_enabled():
        return {"found": [], "source_counts": {}, "raw_records": []}

    sources = _configured_deep_sources(all_sources)
    if not sources:
        return {"found": [], "source_counts": {}, "raw_records": []}

    max_depth = _env_int("SUBDOMAIN_DEEP_SCAN_DEPTH", 3, minimum=1, maximum=10)
    targets_per_root = _env_int("SUBDOMAIN_DEEP_TARGETS_PER_ROOT", 40, minimum=1, maximum=500)
    max_tasks = _env_int("SUBDOMAIN_DEEP_MAX_TASKS", 500, minimum=1, maximum=5000)
    phase_timeout = _env_int("SUBDOMAIN_DEEP_PHASE_TIMEOUT_SECONDS", 300, minimum=30, maximum=7200)

    known = sorted(set(discovered))
    total_found: Set[str] = set()
    raw_records: List[Dict[str, object]] = []
    source_counts: Dict[str, int] = {}
    seen_targets: Set[str] = set(root_domains)

    for depth in range(1, max_depth + 1):
        target_zones: List[str] = []
        for root_domain in root_domains:
            target_zones.extend(_deep_scan_targets(root_domain, known, seen_targets, targets_per_root))
        if not target_zones:
            break
        target_zones = target_zones[: max(1, max_tasks // max(1, len(sources)))]
        seen_targets.update(target_zones)

        tasks = [
            (f"deep:{source_name}:d{depth}", source_fn, target_zone)
            for target_zone in target_zones
            for source_name, source_fn in sources.items()
        ][:max_tasks]
        deep_workers = max(4, min(64, len(tasks)))
        pool = ThreadPoolExecutor(max_workers=deep_workers)
        depth_found: Set[str] = set()
        try:
            future_map = {
                pool.submit(_run_passive_source, source_name, source_fn, target_zone): (source_name, target_zone)
                for source_name, source_fn, target_zone in tasks
            }
            for future, source_info, timed_out in _iter_completed_with_deadline(
                future_map,
                phase_timeout,
                f"deep passive enumeration depth {depth}",
            ):
                source_name, target_zone = source_info
                if timed_out:
                    run = {
                        "source": source_name,
                        "root_domain": target_zone,
                        "status": "timeout",
                        "found": [],
                        "found_count": 0,
                        "stderr": f"Deep passive source timed out after {phase_timeout}s",
                    }
                else:
                    run = future.result()
                found = _filter_hosts_for_root(run.get("found") or [], target_zone)
                if found:
                    depth_found.update(found)
                    source_counts[source_name] = source_counts.get(source_name, 0) + len(found)
                raw_records.append(_compact_raw_record(run, sample_size=_env_int("SUBFINDER_RAW_SAMPLE_SIZE", 50, minimum=0)))
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        new_depth_hosts = depth_found - set(known)
        if not new_depth_hosts:
            continue
        total_found.update(new_depth_hosts)
        known = sorted(set(known) | new_depth_hosts)

    return {"found": sorted(total_found), "source_counts": source_counts, "raw_records": raw_records}


def _mutation_labels_from_hosts(root_domain: str, known_hosts: List[str], max_labels: int = 120) -> List[str]:
    labels: Set[str] = set()
    for host in known_hosts:
        if not _is_host_within_root(host, root_domain):
            continue
        left = host[:-len(root_domain)].rstrip('.')
        if not left:
            continue
        for part in left.split('.'):
            token = (part or '').strip().lower()
            if re.fullmatch(r"[a-z0-9-]{2,32}", token):
                labels.add(token)
                if '-' in token:
                    labels.update(x for x in token.split('-') if re.fullmatch(r"[a-z0-9]{2,16}", x))
    return sorted(labels)[:max_labels]


def _generate_permutation_candidates(root_domain: str, known_hosts: List[str], max_candidates: int = 1200) -> Set[str]:
    seed_labels = _mutation_labels_from_hosts(root_domain, known_hosts)
    brute_labels = _brute_labels()
    candidates: Set[str] = set()
    deep_suffix_limit = _env_int("DNS_PERMUTATION_SUFFIXES_PER_HOST", 5, minimum=1, maximum=25)
    suffixes: Set[str] = {root_domain}
    for host in known_hosts:
        suffixes.update(_host_suffixes_under_root(host, root_domain, max_depth=deep_suffix_limit))
    for zone in sorted(suffixes, key=lambda host: (-host.count("."), host))[:200]:
        for base in seed_labels[:60]:
            for prefix in ("dev", "staging", "prod", "internal", "edge", "api", "old", "new"):
                candidates.add(f"{prefix}-{base}.{zone}")
            for suffix in ("dev", "stg", "prod", "v2", "v3", "int"):
                candidates.add(f"{base}-{suffix}.{zone}")
        for left in seed_labels[:35]:
            for right in brute_labels[:18]:
                candidates.add(f"{left}.{right}.{zone}")
                candidates.add(f"{right}.{left}.{zone}")
    filtered = {c for c in candidates if _HOST_RE.match(c)}
    if max_candidates > 0 and len(filtered) > max_candidates:
        return set(sorted(filtered)[:max_candidates])
    return filtered


def _permutation_dns_hosts(root_domain: str, known_hosts: List[str], max_candidates: int = 0) -> List[str]:
    if max_candidates <= 0:
        max_candidates = _env_int("DNS_PERMUTATION_MAX_CANDIDATES", 5000, minimum=1, maximum=1_000_000)
    candidates = sorted(_generate_permutation_candidates(root_domain, known_hosts, max_candidates=max_candidates))
    if not candidates:
        return []
    resolved: List[str] = []
    workers = max(8, min(96, len(candidates)))
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


def _subfinder_ssl_scan_targets(discovered: List[str], new_hosts: List[str]) -> List[str]:
    targets = discovered if _env_bool("SUBFINDER_SCAN_ALL_DISCOVERED", False) else new_hosts
    return sorted(set(targets))


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
        feature_set=["subfinder", *_passive_enumeration_sources().keys(), "deep_recursive_passive", "dns_bruteforce", "dns_permutation"],
    )

    job_id = subfinder_job_create(project_id, ",".join(root_domains), triggered_by)

    with _sf_lock:
        _sf_state[project_id] = {"status": "running", "job_id": job_id, "new_count": 0}

    try:
        raw_records = []
        discovered_all: List[str] = []
        source_counts: Dict[str, int] = {}
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
        subfinder_pool = ThreadPoolExecutor(max_workers=workers)
        try:
            futures = {subfinder_pool.submit(_run_subfinder_for_root, root_domain): root_domain for root_domain in root_domains}
            phase_timeout = _env_int("SUBFINDER_TOOL_PHASE_TIMEOUT_SECONDS", 240, minimum=30, maximum=3600)
            for future, root_domain, timed_out in _iter_completed_with_deadline(futures, phase_timeout, "subfinder tool"):
                if timed_out:
                    msg = f"Subfinder phase timed out after {phase_timeout}s for {root_domain}"
                    run = {
                        "root_domain": root_domain,
                        "command": " ".join(_build_subfinder_cmd("subfinder", root_domain)),
                        "status": "timeout",
                        "exit_code": None,
                        "stdout": "",
                        "stderr": msg,
                        "found": [],
                    }
                else:
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
                source_counts["subfinder"] = source_counts.get("subfinder", 0) + len(run["found"])
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
        finally:
            subfinder_pool.shutdown(wait=False, cancel_futures=True)

        discovered = sorted(set(discovered_all))
        osint_sources = _passive_enumeration_sources()
        osint_tasks = [
            (source_name, source_fn, root_domain)
            for source_name, source_fn in osint_sources.items()
            for root_domain in root_domains
        ]
        if osint_tasks:
            osint_workers = max(4, min(64, len(osint_tasks)))
            osint_pool = ThreadPoolExecutor(max_workers=osint_workers)
            try:
                future_map = {
                    osint_pool.submit(_run_passive_source, source_name, source_fn, root_domain): (source_name, root_domain)
                    for source_name, source_fn, root_domain in osint_tasks
                }
                phase_timeout = _env_int("PASSIVE_ENUM_PHASE_TIMEOUT_SECONDS", 240, minimum=30, maximum=3600)
                for future, source_info, timed_out in _iter_completed_with_deadline(future_map, phase_timeout, "passive enumeration"):
                    source_name, root_domain = source_info
                    if timed_out:
                        run = {
                            "source": source_name,
                            "root_domain": root_domain,
                            "status": "timeout",
                            "found": [],
                            "found_count": 0,
                            "stderr": f"Passive source timed out after {phase_timeout}s",
                        }
                    else:
                        run = future.result()
                    found = run.get("found") or []
                    discovered.extend(found)
                    if found:
                        source_counts[source_name] = source_counts.get(source_name, 0) + len(found)
                    raw_records.append(_compact_raw_record(run, sample_size=_env_int("SUBFINDER_RAW_SAMPLE_SIZE", 50, minimum=0)))
                    rid = subfinder_raw_result_add(
                        job_id=job_id,
                        project_id=project_id,
                        root_domain=root_domain,
                        command=f"{source_name}:{root_domain}",
                    )
                    subfinder_raw_result_finish(
                        rid,
                        run.get("status", "done"),
                        0 if run.get("status") == "done" else 1,
                        len(found),
                        "\n".join(found),
                        run.get("stderr", ""),
                    )
            finally:
                osint_pool.shutdown(wait=False, cancel_futures=True)
        deep_run = _run_recursive_passive_enumeration(root_domains, discovered, osint_sources)
        deep_found = deep_run.get("found") or []
        if deep_found:
            discovered.extend(deep_found)
        for source_name, count in (deep_run.get("source_counts") or {}).items():
            source_counts[source_name] = source_counts.get(source_name, 0) + int(count or 0)
        raw_records.extend(deep_run.get("raw_records") or [])

        discovered = sorted(set(discovered))
        brute_discovered: Set[str] = set()
        permutation_discovered: Set[str] = set()
        if _dns_bruteforce_enabled():
            brute_tasks = [("dns_bruteforce", root_domain) for root_domain in root_domains]
            permutation_tasks = [("dns_permutation", root_domain) for root_domain in root_domains]
            mutation_seed_hosts = discovered + root_domains
            dns_pool = ThreadPoolExecutor(max_workers=max(4, min(24, len(brute_tasks) + len(permutation_tasks))))
            try:
                future_map = {}
                for source_name, root_domain in brute_tasks:
                    future_map[dns_pool.submit(_bruteforce_dns_hosts, root_domain, mutation_seed_hosts)] = (source_name, root_domain)
                for source_name, root_domain in permutation_tasks:
                    future_map[dns_pool.submit(_permutation_dns_hosts, root_domain, mutation_seed_hosts)] = (source_name, root_domain)
                phase_timeout = _env_int("DNS_ENUM_PHASE_TIMEOUT_SECONDS", 180, minimum=15, maximum=3600)
                for future, source_info, timed_out in _iter_completed_with_deadline(future_map, phase_timeout, "DNS enumeration"):
                    source_name, root_domain = source_info
                    if timed_out:
                        log.warning("DNS mutation source timed out source=%s root=%s", source_name, root_domain)
                        continue
                    try:
                        found = set(future.result() or [])
                    except Exception as e:
                        log.warning("DNS mutation source failed source=%s root=%s err=%s", source_name, root_domain, e)
                        continue
                    if source_name == "dns_bruteforce":
                        brute_discovered.update(found)
                    else:
                        permutation_discovered.update(found)
            finally:
                dns_pool.shutdown(wait=False, cancel_futures=True)
            if brute_discovered:
                source_counts["dns_bruteforce"] = len(brute_discovered)
                discovered = sorted(set(discovered) | brute_discovered)
            if permutation_discovered:
                source_counts["dns_permutation"] = len(permutation_discovered)
                discovered = sorted(set(discovered) | permutation_discovered)
        else:
            log.info("DNS brute-force discovery disabled via DNS_BRUTEFORCE_ENABLED")
        new_count, new_hosts = subfinder_hosts_add_batch(project_id, discovered)
        subfinder_new_discoveries_add_batch(job_id, project_id, new_hosts)
        httpx_rows = _resolve_active_hosts_with_httpx(new_hosts)
        subfinder_httpx_results_upsert_batch(project_id, job_id, httpx_rows)

        raw_output_path = ""
        if os.getenv("SUBFINDER_STORE_RAW_FILE", "0").strip().lower() not in {"0", "false", "no", "off"}:
            raw_dir = Path("data/subfinder_raw")
            raw_dir.mkdir(parents=True, exist_ok=True)
            path = raw_dir / f"{job_id}.json.gz"
            compact_records = [
                _compact_raw_record(record, sample_size=_env_int("SUBFINDER_RAW_SAMPLE_SIZE", 50, minimum=0))
                for record in raw_records
            ]
            with gzip.open(path, "wt", encoding="utf-8") as fp:
                json.dump(compact_records, fp, separators=(",", ":"))
            raw_output_path = str(path)
        subfinder_job_finish(job_id, new_count, len(discovered), raw_output_path)
        log_event("subfinder", "info", "Enumeration source summary", project_id=project_id, job_id=job_id, sources=source_counts, total_discovered=len(discovered))

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

        # SSL scan only newly discovered hosts by default. Re-scanning every
        # previously known host on each enumeration run can make subfinder jobs
        # appear stuck for very large projects. Operators who want the old
        # behavior can opt in with SUBFINDER_SCAN_ALL_DISCOVERED=1.
        scan_hosts = _subfinder_ssl_scan_targets(discovered, new_hosts)
        if scan_hosts:
            _ssl_scan_subfinder_hosts(project_id, scan_hosts, job_id)

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

    max_scan_hosts = _env_int("SUBFINDER_SSL_SCAN_MAX_HOSTS", 2000, minimum=1, maximum=1_000_000)
    if len(hostnames) > max_scan_hosts:
        log.warning(
            "Subfinder SSL scan host list capped at %d of %d hosts; set SUBFINDER_SSL_SCAN_MAX_HOSTS to raise this limit",
            max_scan_hosts,
            len(hostnames),
        )
        hostnames = sorted(set(hostnames))[:max_scan_hosts]

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


def run_domain_enumeration_scan(domain: str, triggered_by: str = "manual") -> dict:
    import db.database as db

    root = _normalize_host(domain)
    if not root or "." not in root:
        raise ValueError("Invalid domain")

    scan_id = db.domain_enum_scan_create(
        root,
        triggered_by=triggered_by,
        tool_summary=_tool_summary(),
    )
    all_found: Set[str] = set()
    source_map: Dict[str, Set[str]] = {}

    passive_sources = _passive_enumeration_sources()
    max_workers = max(8, min(64, len(passive_sources) + 1))
    enum_pool = ThreadPoolExecutor(max_workers=max_workers)
    try:
        future_map = {enum_pool.submit(_run_subfinder_for_root, root, 220): "subfinder"}
        future_map.update(
            {
                enum_pool.submit(_run_passive_source, source_name, source_fn, root): source_name
                for source_name, source_fn in passive_sources.items()
            }
        )

        phase_timeout = _env_int("DOMAIN_ENUM_PHASE_TIMEOUT_SECONDS", 240, minimum=30, maximum=3600)
        for fut, src, timed_out in _iter_completed_with_deadline(future_map, phase_timeout, "domain enumeration"):
            if timed_out:
                continue
            try:
                result = fut.result()
                hosts = (result.get("found") or []) if isinstance(result, dict) else (result or [])
                for h in hosts:
                    if h and _HOST_RE.match(h) and _is_host_within_root(h, root):
                        source_map.setdefault(src, set()).add(h)
                        all_found.add(h)
            except Exception:
                continue
    finally:
        enum_pool.shutdown(wait=False, cancel_futures=True)

    seed_hosts = list(all_found) or [root]
    dns_pool = ThreadPoolExecutor(max_workers=2)
    try:
        future_map = {
            dns_pool.submit(_bruteforce_dns_hosts, root, seed_hosts, 2500): "dns_bruteforce",
            dns_pool.submit(_permutation_dns_hosts, root, seed_hosts, 2500): "dns_permutation",
        }
        phase_timeout = _env_int("DOMAIN_DNS_ENUM_PHASE_TIMEOUT_SECONDS", 180, minimum=15, maximum=3600)
        for fut, src, timed_out in _iter_completed_with_deadline(future_map, phase_timeout, "domain DNS enumeration"):
            if timed_out:
                continue
            try:
                hosts = fut.result() or []
            except Exception:
                continue
            for h in hosts:
                if _is_host_within_root(h, root):
                    source_map.setdefault(src, set()).add(h)
                    all_found.add(h)
    finally:
        dns_pool.shutdown(wait=False, cancel_futures=True)

    for src, hosts in source_map.items():
        if hosts:
            db.domain_enum_results_add_batch(scan_id, root, sorted(hosts), source=src)
    db.domain_enum_scan_finish(scan_id, "done", total_found=len(all_found))
    return {"scan_id": scan_id, "domain": root, "total_found": len(all_found)}


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
