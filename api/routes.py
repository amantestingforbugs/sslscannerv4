"""
api/routes.py — All REST endpoints + SSE stream for real-time UI updates.
Fixes:
  - Alert clear now pushes SSE event so counter resets without page refresh
  - All heavy ops are async — create_project is instant
  - Added /api/sse for real-time push to browser
  - Subfinder CRUD endpoints
"""

import json
import csv
import io
import queue
import threading
import time
import logging
import os
import subprocess
import shutil
import tempfile
import signal
import hmac
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify, Response, stream_with_context

import db.database as db
from core.ssl_checker import parse_hosts_file
from core.target_policy import (
    allow_private_targets,
    allowed_scope_domains,
    is_ip_disallowed,
    is_target_allowed,
    normalize_hostname as normalize_target_hostname,
    registered_domain,
)
from core.observability import subscribe, get_logs
from scheduler.runner import (
    run_project_scan_async,
    get_scan_state,
    list_active_scans,
    pause_scan,
    resume_scan,
    stop_scan,
)
from alerts.notifiers import WebhookNotifier, TelegramNotifier

log = logging.getLogger(__name__)
api = Blueprint("api", __name__, url_prefix="/api")

# ── SSE broadcast bus ─────────────────────────────────────────────────────────
# Each connected browser gets its own queue. Events pushed here reach all clients.
_sse_clients: list[queue.Queue] = []
_sse_lock = threading.Lock()
_openssl_threads: dict[str, threading.Thread] = {}
_openssl_status: dict[str, dict] = {}
_openssl_lock = threading.Lock()
_quick_scan_threads: dict[str, threading.Thread] = {}
_quick_scan_state: dict[str, dict] = {}
_quick_scan_lock = threading.Lock()
_nuclei_threads: dict[str, threading.Thread] = {}
_nuclei_state: dict[str, dict] = {}
_nuclei_lock = threading.Lock()
NUCLEI_LOG_BUFFER = 600
QUICK_SCAN_ROWS_BUFFER = 500
STARTED_AT_TS = time.time()



def _safe_int(value, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if min_value is not None:
        parsed = max(min_value, parsed)
    if max_value is not None:
        parsed = min(max_value, parsed)
    return parsed


def _is_private_or_local_host(host: str) -> bool:
    h = (host or "").strip().lower()
    if h in {"localhost", "127.0.0.1", "::1"}:
        return True
    return (not allow_private_targets()) and is_ip_disallowed(h)


def _resolve_nuclei_binary() -> str | None:
    configured = os.environ.get("NUCLEI_BIN", "").strip()
    if configured and os.path.isfile(configured) and os.access(configured, os.X_OK):
        return configured

    bin_path = shutil.which("nuclei")
    if bin_path:
        return bin_path

    for candidate in ("/root/go/bin/nuclei", "/usr/local/bin/nuclei", "/usr/bin/nuclei"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _nuclei_templates_dir() -> str:
    return os.environ.get("NUCLEI_TEMPLATES_DIR", "").strip() or os.path.expanduser("~/nuclei-templates")


def _directory_has_files(path: str) -> bool:
    if not os.path.isdir(path):
        return False
    return any(os.path.isfile(os.path.join(root, name)) for root, _, files in os.walk(path) for name in files)


def _ensure_nuclei_templates(nuclei_bin: str) -> tuple[bool, str]:
    """
    Ensure nuclei templates exist locally.
    Returns (ok, message). Non-empty message is informational/warning text.
    """
    templates_dir = _nuclei_templates_dir()
    if _directory_has_files(templates_dir):
        return True, "templates already present"

    try:
        os.makedirs(templates_dir, exist_ok=True)
        init_run = subprocess.run(
            [nuclei_bin, "-ut", "-ud", templates_dir],
            text=True,
            capture_output=True,
            timeout=300,
        )
        if init_run.returncode == 0 and _directory_has_files(templates_dir):
            return True, "Nuclei templates were missing and have been downloaded."
        detail = (init_run.stderr or init_run.stdout or "").strip()
        if not detail:
            detail = f"nuclei exited with code {init_run.returncode}"
        return False, f"Failed to download nuclei templates automatically. {detail}"
    except Exception as ex:
        return False, f"Failed to download nuclei templates automatically: {ex}"


def _normalize_nuclei_target(raw: str) -> str:
    host = normalize_target_hostname(raw, allow_ip=True)
    if not host or not is_target_allowed(host):
        return ""
    return host


def _normalize_nuclei_finding(row: dict) -> dict:
    info = row.get("info") or {}
    severity = (info.get("severity") or row.get("severity") or "unknown").lower()
    template_id = row.get("template_id") or row.get("template-id") or row.get("templateID") or ""
    matched_at = row.get("matched_at") or row.get("matched-at") or row.get("matched") or row.get("url") or ""
    host = row.get("host") or row.get("ip") or ""
    if isinstance(host, list):
        host = ", ".join(str(h) for h in host)
    return {
        **row,
        "host": host or matched_at,
        "matched_at": matched_at,
        "template_id": template_id,
        "info": {**info, "severity": severity, "name": info.get("name") or row.get("name") or template_id or "—"},
    }

def _validate_webhook_url(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("Webhook URLs must be valid https URLs")
    host = (parsed.hostname or "").strip().lower()
    if not host or _is_private_or_local_host(host):
        raise ValueError("Webhook URL host is not allowed")
    return value


def broadcast(event: str, data: dict):
    """Push an event to all connected SSE clients."""
    msg = f"event: {event}\ndata: {json.dumps(data)}\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)


def _handle_observability_event(evt: dict):
    event_name = evt.get("event")
    if event_name:
        payload = {k: v for k, v in evt.items() if k != "event"}
        broadcast(event_name, payload)


subscribe(_handle_observability_event)


def _api_key_required() -> bool:
    return os.getenv("API_REQUIRE_KEY", "").strip().lower() in {"1", "true", "yes", "on"}


def _configured_api_key() -> str:
    return os.getenv("API_KEY", "").strip() or os.getenv("SSL_SENTINEL_API_KEY", "").strip()


@api.before_request
def require_api_key():
    """Optional API-key gate for company deployments.

    The default stays open for local development/tests, but production can set
    API_REQUIRE_KEY=true and API_KEY=<secret>. Mutating scanner endpoints then
    require X-API-Key or Authorization: Bearer <secret>.
    """
    if not _api_key_required():
        return None
    expected = _configured_api_key()
    if not expected:
        return err("API key enforcement is enabled but API_KEY is not configured", 503)
    supplied = (request.headers.get("X-API-Key") or "").strip()
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        supplied = auth.split(None, 1)[1].strip()
    if hmac.compare_digest(supplied, expected):
        return None
    return err("Unauthorized", 401)


# ── Helpers ───────────────────────────────────────────────────────────────────

def ok(data=None, **kw):
    p = {"ok": True}
    if data is not None: p["data"] = data
    p.update(kw)
    return jsonify(p)


def err(msg, code=400):
    return jsonify({"ok": False, "error": msg}), code


def _normalize_hostname(raw: str) -> str:
    host = normalize_target_hostname(raw)
    if not host or not is_target_allowed(host):
        return ""
    return host



def _analyze_hosts_text(content: str) -> dict:
    """Return normalized host inventory metadata before saving a pasted/uploaded list."""
    raw_items = []
    for line in (content or "").splitlines():
        item = line.split("#", 1)[0].strip()
        if item:
            raw_items.append(item)

    normalized = []
    invalid = []
    seen = set()
    duplicates = []
    for raw in raw_items:
        host = _normalize_hostname(raw)
        if not host:
            invalid.append(raw)
            continue
        if host in seen:
            duplicates.append(host)
            continue
        seen.add(host)
        normalized.append(host)

    return {
        "hosts": normalized,
        "host_count": len(normalized),
        "input_count": len(raw_items),
        "invalid_count": len(invalid),
        "duplicate_count": len(duplicates),
        "invalid_samples": invalid[:25],
        "duplicate_samples": duplicates[:25],
        "scope_domains": allowed_scope_domains(),
        "private_targets_allowed": allow_private_targets(),
    }



def _compute_risk_intelligence(total_hosts: int, latest: dict, previous: dict | None = None) -> dict:
    """Compute normalized risk score, grade, trend, and prioritized actions."""
    total = max(1, int(total_hosts or 0))
    mismatches = int((latest or {}).get("mismatches") or 0)
    expired = int((latest or {}).get("expired") or 0)
    expiring = int((latest or {}).get("expiring") or 0)
    errors = int((latest or {}).get("errors") or 0)

    weighted = (expired * 45) + (mismatches * 30) + (expiring * 15) + (errors * 10)
    max_weight = total * 45
    score = min(100, round((weighted / max_weight) * 100, 2)) if max_weight > 0 else 0

    if score >= 75:
        grade = "critical"
    elif score >= 50:
        grade = "high"
    elif score >= 25:
        grade = "medium"
    else:
        grade = "low"

    prev_score = None
    trend = "stable"
    if previous:
        prev = _compute_risk_intelligence(total, previous, None)
        prev_score = prev["score"]
        delta = round(score - prev_score, 2)
        trend = "up" if delta > 0.5 else ("down" if delta < -0.5 else "stable")

    actions = []
    if expired:
        actions.append({"priority": 1, "title": "Rotate expired certificates", "count": expired})
    if mismatches:
        actions.append({"priority": 2, "title": "Fix certificate hostname mismatches", "count": mismatches})
    if expiring:
        actions.append({"priority": 3, "title": "Renew certificates expiring soon", "count": expiring})
    if errors:
        actions.append({"priority": 4, "title": "Investigate persistent TLS scan errors", "count": errors})

    exposure = {
        "expired_pct": round((expired / total) * 100, 2),
        "mismatch_pct": round((mismatches / total) * 100, 2),
        "expiring_pct": round((expiring / total) * 100, 2),
        "error_pct": round((errors / total) * 100, 2),
    }

    return {
        "score": score,
        "grade": grade,
        "trend": trend,
        "previous_score": prev_score,
        "total_hosts": total_hosts,
        "latest": {
            "mismatches": mismatches,
            "expired": expired,
            "expiring": expiring,
            "errors": errors,
        },
        "exposure": exposure,
        "recommended_actions": actions,
    }
def _run_openssl_subject(hostname: str, timeout: int = 20) -> dict:
    cmd = ["openssl", "s_client", "-connect", f"{hostname}:443"]
    try:
        run = subprocess.run(
            cmd,
            input="",
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        lines = [ln.strip() for ln in (run.stdout or "").splitlines() if "subject" in ln.lower()]
        subject = lines[0] if lines else ""
        return {
            "hostname": hostname,
            "subject": subject or "subject not found",
            "status": "ok" if subject else "no_subject",
            "exit_code": run.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"hostname": hostname, "subject": "", "status": "timeout", "error": f"timeout after {timeout}s"}
    except FileNotFoundError:
        return {"hostname": hostname, "subject": "", "status": "error", "error": "openssl binary not found"}
    except Exception as e:
        return {"hostname": hostname, "subject": "", "status": "error", "error": str(e)}


def _collect_openssl_hosts(pid: str) -> list[str]:
    base_hosts = {_normalize_hostname(h) for h in db.project_hosts(pid)}
    sf_hosts = {
        _normalize_hostname(r["hostname"])
        for r in db.x("SELECT hostname FROM subfinder_hosts WHERE project_id=?", (pid,)).fetchall()
    }
    return sorted({h for h in (base_hosts | sf_hosts) if h})


def _start_quick_scan(hosts: list[str]) -> str:
    sid = db.uid()
    with _quick_scan_lock:
        _quick_scan_state[sid] = {
            "id": sid,
            "status": "running",
            "source": "quick_scan",
            "total": len(hosts),
            "done": 0,
            "ok": 0,
            "mismatches": 0,
            "expired": 0,
            "expiring": 0,
            "errors": 0,
            "hosts": hosts,
            "rows": [],
            "rows_total": 0,
            "started_at": db.now(),
            "finished_at": None,
        }
    th = threading.Thread(target=_quick_scan_worker, args=(sid,), daemon=True, name=f"quick-scan-{sid[:8]}")
    with _quick_scan_lock:
        _quick_scan_threads[sid] = th
    th.start()
    return sid


def _quick_scan_worker(sid: str):
    from core.ssl_checker import run_checker

    with _quick_scan_lock:
        state = _quick_scan_state.get(sid)
        hosts = list(state.get("hosts") or []) if state else []
    if not hosts:
        with _quick_scan_lock:
            if sid in _quick_scan_state:
                _quick_scan_state[sid]["status"] = "error"
                _quick_scan_state[sid]["finished_at"] = db.now()
        return

    def _on_result(done: int, total: int, row: dict):
        row = dict(row or {})
        row.setdefault("hostname", "")
        row.setdefault("cn", "")
        row.setdefault("issuer", "")
        row.setdefault("expiry", "")
        row.setdefault("days_left", None)
        row["is_expiring"] = bool(row.get("is_expiring_soon"))
        with _quick_scan_lock:
            state = _quick_scan_state.get(sid)
            if not state:
                return
            state["rows"].append(row)
            state["rows_total"] = int(state.get("rows_total") or 0) + 1
            if len(state["rows"]) > QUICK_SCAN_ROWS_BUFFER:
                state["rows"] = state["rows"][-QUICK_SCAN_ROWS_BUFFER:]
            state["done"] = done
            state["ok"] += 1 if row.get("is_ok") else 0
            state["mismatches"] += 1 if row.get("is_mismatch") else 0
            state["expired"] += 1 if row.get("is_expired") else 0
            state["expiring"] += 1 if row.get("is_expiring_soon") else 0
            state["errors"] += 1 if row.get("error") else 0
            payload = {
                "id": sid,
                "status": "running",
                "total": total,
                "done": done,
                "ok": state["ok"],
                "mismatches": state["mismatches"],
                "expired": state["expired"],
                "expiring": state["expiring"],
                "errors": state["errors"],
            }
        broadcast("quick_scan_row", {"scan_id": sid, "row": row})
        broadcast("quick_scan_update", payload)

    try:
        # Quick scans run on-demand and often from low-resource dynos/containers.
        # Keep worker count conservative to avoid "can't start new thread" and
        # premature scan termination a few seconds after start.
        quick_workers = max(4, min(32, len(hosts)))
        run_checker(
            hosts,
            max_workers=quick_workers,
            progress_callback=_on_result,
            collect_results=False,
        )
        with _quick_scan_lock:
            state = _quick_scan_state.get(sid)
            if state:
                state["status"] = "done"
                state["finished_at"] = db.now()
                state["hosts"] = []
                payload = {
                    "id": sid,
                    "status": "done",
                    "total": state["total"],
                    "done": state["done"],
                    "ok": state["ok"],
                    "mismatches": state["mismatches"],
                    "expired": state["expired"],
                    "expiring": state["expiring"],
                    "errors": state["errors"],
                    "finished_at": state["finished_at"],
                }
        broadcast("quick_scan_update", payload)
    except Exception as e:
        with _quick_scan_lock:
            state = _quick_scan_state.get(sid)
            if state:
                state["status"] = "error"
                state["error"] = str(e)
                state["finished_at"] = db.now()
                state["hosts"] = []
                payload = {
                    "id": sid,
                    "status": "error",
                    "error": str(e),
                    "total": state["total"],
                    "done": state["done"],
                }
        broadcast("quick_scan_update", payload)


def _start_openssl_worker(pid: str, source: str = "manual") -> bool:
    with _openssl_lock:
        existing = _openssl_threads.get(pid)
        if existing and existing.is_alive():
            return False
        _openssl_status[pid] = {
            "status": "running",
            "source": source,
            "started_at": time.time(),
            "last_tick": time.time(),
            "processed_total": 0,
            "new_hosts_scanned": 0,
        }
        th = threading.Thread(target=_openssl_worker_loop, args=(pid, source), daemon=True, name=f"openssl-{pid[:8]}")
        _openssl_threads[pid] = th
        th.start()
        return True


def _openssl_worker_loop(pid: str, source: str):
    try:
        while True:
            if not db.project_get(pid):
                break
            known = {r["hostname"] for r in db.openssl_results_list(pid, limit=5000)}
            hosts = _collect_openssl_hosts(pid)
            pending = [h for h in hosts if h not in known]

            with _openssl_lock:
                if pid in _openssl_status:
                    _openssl_status[pid]["last_tick"] = time.time()

            if not pending:
                broadcast("openssl_status", {"project_id": pid, "status": "idle_waiting", "tracked_hosts": len(hosts)})
                time.sleep(10)
                continue

            rows = []
            for hostname in pending:
                row = _run_openssl_subject(hostname)
                rows.append(row)
                db.openssl_results_upsert_batch(pid, [row], source=source)
                with _openssl_lock:
                    if pid in _openssl_status:
                        _openssl_status[pid]["processed_total"] += 1
                        _openssl_status[pid]["new_hosts_scanned"] += 1
                broadcast("openssl_row", {"project_id": pid, "row": row})

            broadcast("openssl_status", {
                "project_id": pid,
                "status": "running",
                "processed": len(rows),
                "pending_after": 0,
                "tracked_hosts": len(hosts),
            })
            time.sleep(2)
    finally:
        with _openssl_lock:
            if pid in _openssl_status:
                _openssl_status[pid]["status"] = "stopped"
        broadcast("openssl_status", {"project_id": pid, "status": "stopped"})


# ── SSE stream ────────────────────────────────────────────────────────────────

@api.get("/sse")
def sse_stream():
    """
    Server-Sent Events endpoint. Browser connects once and receives live events:
      - alert_update: {unseen_count}
      - scan_update:  {scan_id, progress, total, status}
      - stats_update: {mismatches, expired, ...}
    """
    q = queue.Queue(maxsize=50)
    with _sse_lock:
        _sse_clients.append(q)

    def generate():
        # Send initial heartbeat
        yield f"event: connected\ndata: {{}}\n\n"
        try:
            while True:
                try:
                    msg = q.get(timeout=25)
                    yield msg
                except queue.Empty:
                    # Heartbeat to keep connection alive (Railway times out at 30s)
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                if q in _sse_clients:
                    _sse_clients.remove(q)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering
        }
    )


# ── Projects ──────────────────────────────────────────────────────────────────

@api.get("/projects")
def list_projects():
    projects = db.project_list()
    for p in projects:
        p["latest_scan"] = db.scan_latest(p["id"])
    return ok(projects)


@api.post("/projects")
def create_project():
    d = request.json or {}
    name = (d.get("name") or "").strip()
    if not name:
        return err("name is required")
    if db.project_get_by_name(name):
        return err("A project with that name already exists")
    p = db.project_create(
        name,
        d.get("description", ""),
        _safe_int(d.get("scan_interval", 60), 60, min_value=5, max_value=10080),
        _safe_int(d.get("subfinder_interval", 30), 30, min_value=5, max_value=10080),
    )
    broadcast("project_created", {"id": p["id"], "name": p["name"]})
    return ok(p)


@api.get("/projects/<pid>")
def get_project(pid):
    p = db.project_get(pid)
    if not p: return err("Not found", 404)
    p["latest_scan"] = db.scan_latest(pid)
    return ok(p)


@api.put("/projects/<pid>")
def update_project(pid):
    d = request.json or {}
    allowed = {"name","description","scan_interval_minutes","subfinder_interval_minutes",
               "subfinder_enabled","enabled"}
    kw = {k: v for k, v in d.items() if k in allowed}
    db.project_update(pid, **kw)
    return ok(db.project_get(pid))


@api.delete("/projects/<pid>")
def delete_project(pid):
    db.project_delete(pid)
    broadcast("project_deleted", {"id": pid})
    return ok()


@api.post("/projects/<pid>/hosts")
def upload_hosts(pid):
    if not db.project_get(pid):
        return err("Project not found", 404)
    if "file" in request.files:
        content = request.files["file"].read().decode("utf-8", errors="ignore")
    else:
        content = (request.json or {}).get("hosts", "") or (request.data or b"").decode()
    analysis = _analyze_hosts_text(content)
    hosts = analysis["hosts"]
    if not hosts:
        return err("No valid hostnames found")
    db.project_save_hosts(pid, hosts)
    return ok({"count": len(hosts), "analysis": analysis})


@api.get("/projects/<pid>/hosts")
def get_hosts(pid):
    return ok(db.project_hosts(pid))


@api.post("/projects/<pid>/hosts/preview")
def preview_hosts(pid):
    if not db.project_get(pid):
        return err("Project not found", 404)
    content = (request.json or {}).get("hosts", "") or (request.data or b"").decode(errors="ignore")
    return ok(_analyze_hosts_text(content))


# ── Scans ─────────────────────────────────────────────────────────────────────

@api.post("/projects/<pid>/scan")
def trigger_scan(pid):
    p = db.project_get(pid)
    if not p: return err("Project not found", 404)
    if int(p.get("host_count") or 0) <= 0:
        return err("Upload a host list first")
    if not run_project_scan_async(pid, triggered_by="manual"):
        return err("A scan is already running for this project")
    return ok({"message": "Scan started"})


@api.get("/projects/<pid>/scans")
def list_scans(pid):
    return ok(db.scan_list(pid))


@api.get("/scans/<sid>")
def get_scan(sid):
    s = db.scan_get(sid)
    if not s: return err("Not found", 404)
    live = get_scan_state(sid)
    if live:
        s["live_progress"] = live.get("progress", 0)
        s["live_status"] = live.get("status")
    return ok(s)


@api.get("/scans/<sid>/results")
def get_results(sid):
    flt = request.args.get("filter", "all")
    page = _safe_int(request.args.get("page", 1), 1, min_value=1)
    per_page = _safe_int(request.args.get("per_page", 500), 500, min_value=50, max_value=1000)
    return ok(db.results_get(sid, flt, page, per_page))


@api.get("/scans/<sid>/results/export")
def export_results(sid):
    scan = db.scan_get(sid)
    if not scan:
        return err("Scan not found", 404)
    flt = (request.args.get("filter", "all") or "all").strip().lower()
    if flt not in {"all", "mismatch", "expired", "expiring", "ok", "errors"}:
        return err("Invalid filter", 400)
    rows = db.scan_results_all(sid, flt)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([
        "hostname", "status", "cn", "issuer", "not_before", "expiry", "days_left",
        "tls_version", "cipher_suite", "cipher_bits", "key_algorithm", "key_bits",
        "signature_algorithm", "san_count", "fingerprint_sha256", "serial_number", "error", "checked_at",
    ])
    for r in rows:
        writer.writerow([
            r.get("hostname", ""), _result_status(r), r.get("cn", ""), r.get("issuer", ""),
            r.get("not_before", ""), r.get("expiry", ""), r.get("days_left", ""),
            r.get("tls_version", ""), r.get("cipher_suite", ""), r.get("cipher_bits", ""),
            r.get("key_algorithm", ""), r.get("key_bits", ""), r.get("signature_algorithm", ""),
            r.get("san_count", ""), r.get("fingerprint_sha256", ""), r.get("serial_number", ""),
            r.get("error", ""), r.get("checked_at", ""),
        ])
    filename = f"ssl-scan-{sid[:8]}-{flt}.csv"
    return Response(
        out.getvalue(),
        content_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _result_status(row: dict) -> str:
    if row.get("error"):
        return "error"
    if row.get("is_expired"):
        return "expired"
    if row.get("is_mismatch"):
        return "mismatch"
    if row.get("is_expiring") or row.get("is_expiring_soon"):
        return "expiring"
    if row.get("is_ok"):
        return "ok"
    return "unknown"


@api.get("/scans/<sid>/compare")
def compare_scan(sid):
    if not db.scan_get(sid):
        return err("Scan not found", 404)
    previous_sid = (request.args.get("previous_scan_id") or "").strip() or None
    comparison = db.scan_compare(sid, previous_sid)
    if comparison is None:
        return err("Scan not found", 404)
    return ok(comparison)


@api.get("/active-scans")
def active_scans():
    return ok(list_active_scans())


@api.post("/scans/<sid>/pause")
def pause_scan_route(sid):
    if not db.scan_get(sid):
        return err("Scan not found", 404)
    if not pause_scan(sid):
        return err("Scan is not running", 409)
    live = get_scan_state(sid) or {"id": sid, "status": "paused"}
    db.scan_update(sid, status="paused")
    broadcast("scan_update", {"id": sid, **live, "status": "paused"})
    return ok({"scan_id": sid, "status": "paused"})


@api.post("/scans/<sid>/resume")
def resume_scan_route(sid):
    if not db.scan_get(sid):
        return err("Scan not found", 404)
    if not resume_scan(sid):
        return err("Scan is not paused", 409)
    live = get_scan_state(sid) or {"id": sid, "status": "running"}
    db.scan_update(sid, status="running")
    broadcast("scan_update", {"id": sid, **live, "status": "running"})
    return ok({"scan_id": sid, "status": "running"})


@api.post("/scans/<sid>/stop")
def stop_scan_route(sid):
    if not db.scan_get(sid):
        return err("Scan not found", 404)
    if not stop_scan(sid):
        return err("Scan is not active", 409)
    live = get_scan_state(sid) or {"id": sid, "status": "stopping"}
    db.scan_update(sid, status="stopping")
    broadcast("scan_update", {"id": sid, **live, "status": "stopping"})
    return ok({"scan_id": sid, "status": "stopping"})


@api.post("/quick-scan")
def start_quick_scan():
    d = request.json or {}
    hosts_raw = d.get("hosts", "") or ""
    hosts = parse_hosts_file(hosts_raw)
    hosts = sorted({_normalize_hostname(h) for h in hosts if _normalize_hostname(h)})
    if not hosts:
        return err("Paste at least one valid hostname")
    if len(hosts) > 50000:
        return err("Quick scan supports up to 50000 hosts at once")
    sid = _start_quick_scan(hosts)
    return ok({"scan_id": sid, "total": len(hosts), "status": "running"})


@api.get("/quick-scan/<sid>")
def quick_scan_status(sid):
    with _quick_scan_lock:
        state = dict(_quick_scan_state.get(sid) or {})
    if not state:
        return err("Quick scan not found", 404)
    # Keep status payload tiny so polling remains fast even for large scans.
    state.pop("rows", None)
    state.pop("hosts", None)
    return ok(state)


# ── Alerts ────────────────────────────────────────────────────────────────────

@api.get("/alerts")
def get_alerts():
    search = (request.args.get("search", "") or "").strip()
    mismatch = (request.args.get("mismatch_scope", "all") or "all").strip()
    project_id = (request.args.get("project_id", "") or "").strip()
    page = _safe_int(request.args.get("page", 1), 1, min_value=1)
    per_page = _safe_int(request.args.get("per_page", 200), 200, min_value=50, max_value=1000)
    return ok(db.alerts_get(search=search, mismatch_scope=mismatch, project_id=project_id, page=page, per_page=per_page))


@api.post("/alerts/<aid>/read")
def mark_one_seen(aid):
    db.alert_mark_seen(aid)
    broadcast("alert_update", {"unseen_count": db.alerts_unseen_count()})
    return ok()


@api.post("/alerts/seen")
def mark_seen():
    db.alerts_mark_all_seen()
    # Push SSE so badge resets instantly in all open tabs
    broadcast("alert_update", {"unseen_count": 0})
    return ok()


@api.post("/alerts/clear")
def clear_alerts():
    db.alerts_clear()
    # Push SSE — this is what was missing causing the stale counter bug
    broadcast("alert_update", {"unseen_count": 0})
    return ok()


@api.get("/alert-settings")
def get_alert_settings():
    return ok(db.alert_settings_get())


@api.put("/alert-settings")
def update_alert_settings():
    d = request.json or {}
    previous = db.alert_settings_get()
    try:
        slack_webhook_url = _validate_webhook_url((d.get("slack_webhook_url") or "").strip())
        discord_webhook_url = _validate_webhook_url((d.get("discord_webhook_url") or "").strip())
    except ValueError as e:
        return err(str(e), 400)

    cleaned = {
        "telegram_enabled": d.get("telegram_enabled"),
        "telegram_bot_token": (d.get("telegram_bot_token") or "").strip(),
        "telegram_chat_id": (d.get("telegram_chat_id") or "").strip(),
        "slack_enabled": d.get("slack_enabled"),
        "slack_webhook_url": slack_webhook_url,
        "discord_enabled": d.get("discord_enabled"),
        "discord_webhook_url": discord_webhook_url,
        "rule_mismatch": d.get("rule_mismatch"),
        "rule_expired": d.get("rule_expired"),
        "rule_expiring": d.get("rule_expiring"),
        "rule_error": d.get("rule_error"),
        "mismatch_scope_filter": (d.get("mismatch_scope_filter") or "all").strip(),
        "minimum_days_left": _safe_int(d.get("minimum_days_left", 30), 30, min_value=1, max_value=365),
    }
    out = db.alert_settings_update(**cleaned)

    # Immediately smoke-test enabled channels so broken settings are visible at save-time.
    channel_checks = {}
    sample_alert = [{
        "hostname": "example.com",
        "issue_type": "SSL Mismatch",
        "details": "CN 'wrong.example.com' ≠ hostname",
    }]
    if bool(out.get("slack_enabled")) and (out.get("slack_webhook_url") or "").strip():
        channel_checks["slack"] = bool(
            WebhookNotifier("slack", True, out.get("slack_webhook_url", "")).send_mismatch_digest(
                "Settings Test",
                sample_alert,
            )
        )
    if bool(out.get("discord_enabled")) and (out.get("discord_webhook_url") or "").strip():
        channel_checks["discord"] = bool(
            WebhookNotifier("discord", True, out.get("discord_webhook_url", "")).send_mismatch_digest(
                "Settings Test",
                sample_alert,
            )
        )
    if bool(out.get("telegram_enabled")) and (out.get("telegram_bot_token") or "").strip() and (out.get("telegram_chat_id") or "").strip():
        channel_checks["telegram"] = bool(TelegramNotifier(out).send_mismatch_digest("Settings Test", sample_alert))

    failed_channels = [name for name, passed in channel_checks.items() if not passed]
    if failed_channels:
        return err(f"Saved, but webhook test failed for: {', '.join(failed_channels)}", 400)

    discord_turned_on = bool(out.get("discord_enabled")) and not bool(previous.get("discord_enabled"))
    discord_webhook_changed = (out.get("discord_webhook_url") or "") != (previous.get("discord_webhook_url") or "")
    if bool(out.get("discord_enabled")) and (discord_turned_on or discord_webhook_changed):
        # Re-queue existing unresolved alerts so a newly enabled/updated Discord webhook
        # can receive them on the next scan dispatch.
        db.alerts_mark_all_unsent()
    return ok(out, channel_checks=channel_checks)


# ── Stats ─────────────────────────────────────────────────────────────────────

@api.get("/stats")
def global_stats():
    return ok(db.stats_global())


@api.get("/security-policy")
def security_policy():
    return ok({
        "api_key_required": _api_key_required(),
        "api_key_configured": bool(_configured_api_key()),
        "allowed_scope_domains": allowed_scope_domains(),
        "private_targets_allowed": allow_private_targets(),
        "scope_enforced": bool(allowed_scope_domains()),
    })


@api.get("/projects/<pid>/risk-intelligence")
def project_risk_intelligence(pid):
    p = db.project_get(pid)
    if not p:
        return err("Project not found", 404)

    latest = db.x(
        """
        SELECT id, created_at, finished_at, total, mismatches, expired, expiring, errors, ok
        FROM scans
        WHERE project_id=?
        ORDER BY created_at DESC
        LIMIT 2
        """,
        (pid,),
    ).fetchall()
    if not latest:
        return ok({
            "score": 0,
            "grade": "unknown",
            "trend": "stable",
            "message": "No scans available yet",
            "total_hosts": p.get("host_count", 0),
        })

    current = dict(latest[0])
    previous = dict(latest[1]) if len(latest) > 1 else None
    model = _compute_risk_intelligence(p.get("host_count") or current.get("total") or 0, current, previous)
    model["scan"] = {
        "id": current.get("id"),
        "created_at": current.get("created_at"),
        "finished_at": current.get("finished_at"),
    }
    return ok(model)


@api.get("/system-overview")
def system_overview():
    projects_total = db.x("SELECT COUNT(*) c FROM projects").fetchone()["c"]
    enabled_projects = db.x("SELECT COUNT(*) c FROM projects WHERE enabled=1").fetchone()["c"]
    scans_running = db.x("SELECT COUNT(*) c FROM scans WHERE status='running'").fetchone()["c"]
    latest_scan = db.x("SELECT started_at, status, project_id FROM scans ORDER BY created_at DESC LIMIT 1").fetchone()
    host_inventory = db.x("SELECT COALESCE(SUM(host_count), 0) c FROM projects").fetchone()["c"]
    discoveries = db.x("SELECT COUNT(*) c FROM subfinder_hosts").fetchone()["c"]
    unresolved_alerts = db.x("SELECT COUNT(*) c FROM alerts WHERE seen=0").fetchone()["c"]
    db_file = db.DB_PATH
    uptime_seconds = max(0, int(time.time() - STARTED_AT_TS))
    return ok({
        "uptime_seconds": uptime_seconds,
        "projects_total": projects_total,
        "enabled_projects": enabled_projects,
        "scans_running": scans_running,
        "host_inventory": host_inventory,
        "discoveries_total": discoveries,
        "unresolved_alerts": unresolved_alerts,
        "latest_scan": dict(latest_scan) if latest_scan else None,
        "database": {
            "path": str(db_file),
            "exists": db_file.exists(),
            "size_bytes": db_file.stat().st_size if db_file.exists() else 0,
        },
    })

@api.get("/logs")
def list_logs():
    limit = _safe_int(request.args.get("limit", 200), 200, min_value=20, max_value=1000)
    return ok(get_logs(limit))


# ── Subfinder ─────────────────────────────────────────────────────────────────

@api.post("/projects/<pid>/subfinder/run")
def run_subfinder(pid):
    from subfinder.runner import run_subfinder_async, subfinder_available
    if not pid or pid in {"undefined", "null"}:
        return err("Please select a project before running scan")
    p = db.project_get(pid)
    if not p: return err("Project not found", 404)
    if not db.project_hosts(pid):
        return err("Add a host list first so subfinder knows which root domains to enumerate")
    started = run_subfinder_async(pid, triggered_by="manual")
    if not started:
        return err("Subfinder already running for this project")
    return ok({
        "message": "Subfinder started",
        "binary_found": subfinder_available()
    })


@api.get("/projects/<pid>/subfinder/status")
def subfinder_status(pid):
    from subfinder.runner import get_sf_state, subfinder_available
    return ok({
        "state": get_sf_state(pid),
        "binary_available": subfinder_available(),
        "jobs": db.subfinder_jobs_list(pid, limit=10)
    })


@api.get("/projects/<pid>/subfinder/hosts")
def subfinder_hosts(pid):
    page = _safe_int(request.args.get("page", 1), 1, min_value=1)
    per_page = _safe_int(request.args.get("per_page", 500), 500, min_value=50, max_value=1000)
    return ok(db.subfinder_hosts_list(pid, page, per_page))


@api.get("/projects/<pid>/subfinder/raw-results")
def subfinder_raw_results(pid):
    limit = _safe_int(request.args.get("limit", 20), 20, min_value=1, max_value=100)
    preview_chars = _safe_int(request.args.get("preview_chars", 4000), 4000, min_value=500, max_value=12000)
    return ok(db.subfinder_raw_results_list(pid, limit=limit, preview_chars=preview_chars))


@api.post("/subfinder/enumeration/run")
def run_domain_enumeration():
    from subfinder.runner import run_domain_enumeration_scan
    payload = request.get_json(silent=True) or {}
    domain = (
        payload.get("domain")
        or payload.get("root_domain")
        or request.form.get("domain")
        or request.values.get("domain")
        or request.args.get("domain")
        or ""
    ).strip().lower()
    if not domain:
        return err("Domain is required")
    domain = normalize_target_hostname(domain)
    if not domain:
        return err("Domain must be a valid public hostname", 400)
    root_domain = registered_domain(domain)
    if not is_target_allowed(root_domain):
        return err("Domain is outside configured scan scope or targets a disallowed network", 403)
    try:
        data = run_domain_enumeration_scan(root_domain, triggered_by="manual")
        return ok(data)
    except ValueError as ve:
        return err(str(ve))
    except Exception as e:
        return err(f"Enumeration failed: {e}", 500)


@api.get("/subfinder/enumeration/scans")
def list_domain_enumeration_scans():
    return ok(db.domain_enum_scans_list())


@api.get("/subfinder/enumeration/scans/<scan_id>")
def domain_enumeration_scan_detail(scan_id):
    scan = db.domain_enum_scan_get(scan_id)
    if not scan:
        return err("Not found", 404)
    return ok({"scan": scan, "results": db.domain_enum_results_by_scan(scan_id)})


@api.post("/subfinder/enumeration/scans/<scan_id>/project")
def domain_enumeration_scan_create_project(scan_id):
    scan = db.domain_enum_scan_get(scan_id)
    if not scan:
        return err("Not found", 404)

    rows = db.domain_enum_results_by_scan(scan_id)
    hosts = sorted({
        host for host in (_normalize_hostname(r.get("hostname") or "") for r in rows)
        if host
    })
    if not hosts:
        return err("No in-scope hosts found in this enumeration scan", 400)

    payload = request.get_json(silent=True) or {}
    project_name = (payload.get("name") or payload.get("project_name") or f"Enum {scan.get('domain', '')}").strip()
    if not project_name:
        return err("Project name is required", 400)
    if db.project_get_by_name(project_name):
        return err("A project with that name already exists", 400)

    p = db.project_create(
        project_name,
        payload.get("description", f"Created from enumeration scan {scan_id[:8]} for {scan.get('domain', '')}"),
        _safe_int(payload.get("scan_interval", 60), 60, min_value=5, max_value=10080),
        _safe_int(payload.get("subfinder_interval", 30), 30, min_value=5, max_value=10080),
    )
    db.project_save_hosts(p["id"], hosts)
    broadcast("project_created", {"id": p["id"], "name": p["name"]})
    return ok({"project": db.project_get(p["id"]), "host_count": len(hosts), "scan_id": scan_id})


@api.delete("/subfinder/enumeration/scans/<scan_id>")
def domain_enumeration_scan_delete(scan_id):
    scan = db.domain_enum_scan_get(scan_id)
    if not scan:
        return err("Not found", 404)
    db.domain_enum_scan_delete(scan_id)
    return ok({"deleted": True, "scan_id": scan_id})


@api.get("/subfinder/enumeration/scans/<scan_id>/export")
def domain_enumeration_scan_export(scan_id):
    from subfinder.runner import _resolve_active_hosts_with_httpx

    scan = db.domain_enum_scan_get(scan_id)
    if not scan:
        return err("Not found", 404)
    export_format = (request.args.get("format") or "txt").strip().lower()
    rows = db.domain_enum_results_by_scan(scan_id)
    hosts = [r.get("hostname", "") for r in rows if r.get("hostname")]
    if export_format == "txt":
        payload = "\n".join(sorted(set(hosts))) + ("\n" if hosts else "")
        return Response(
            payload,
            content_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename={scan.get('domain','scan')}-{scan_id[:8]}.txt"},
        )
    if export_format != "csv":
        return err("format must be either txt or csv")

    enrich = _resolve_active_hosts_with_httpx(hosts)
    enrich_map = {r.get("hostname"): r for r in enrich if r.get("hostname")}

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["domain", "subdomain", "source", "discovered_at", "status_code", "scheme", "final_url", "page_title", "is_active", "technologies"])
    for row in rows:
        hx = enrich_map.get(row.get("hostname"), {})
        writer.writerow([
            scan.get("domain", ""),
            row.get("hostname", ""),
            row.get("source", ""),
            row.get("discovered_at", ""),
            hx.get("status_code", ""),
            hx.get("scheme", ""),
            hx.get("final_url", ""),
            hx.get("page_title", ""),
            "yes" if hx.get("is_active") else "no",
            "",
        ])
    return Response(
        out.getvalue(),
        content_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={scan.get('domain','scan')}-{scan_id[:8]}.csv"},
    )


@api.get("/projects/<pid>/discoveries")
def project_discoveries(pid):
    page = _safe_int(request.args.get("page", 1), 1, min_value=1)
    per_page = _safe_int(request.args.get("per_page", 200), 200, min_value=50, max_value=1000)
    search = (request.args.get("search", "") or "").strip()
    mode = (request.args.get("mode", "all") or "all").strip().lower()
    return ok(db.subfinder_discoveries(pid, page, per_page, search, mode=mode))


@api.put("/projects/<pid>/subfinder/toggle")
def toggle_subfinder(pid):
    p = db.project_get(pid)
    if not p: return err("Not found", 404)
    new_val = 0 if p.get("subfinder_enabled") else 1
    db.project_update(pid, subfinder_enabled=new_val)
    return ok({"subfinder_enabled": new_val})




def _resolve_nuclei_hosts(pid: str, mode: str) -> list[str]:
    if mode == "all_subdomains":
        hosts = {_normalize_nuclei_target(h or "") for h in db.project_hosts(pid)}
        rows = db.x("SELECT hostname FROM subfinder_hosts WHERE project_id=?", (pid,)).fetchall()
        hosts |= {_normalize_nuclei_target(r["hostname"] or "") for r in rows}
        return sorted(h for h in hosts if h)

    hosts_data = db.subfinder_discoveries(pid, page=1, per_page=5000, search="", mode="latest")
    return sorted({
        target for target in (_normalize_nuclei_target(r.get("hostname") or "") for r in (hosts_data.get("rows") or []))
        if target
    })


def _nuclei_command(nuclei_bin: str, targets_file: str, templates_dir: str) -> list[str]:
    return [
        nuclei_bin,
        "-l", targets_file,
        "-severity", "medium,high,critical",
        "-jsonl",
        "-stats",
        "-duc",
        "-ud", templates_dir,
        "-t", templates_dir,
    ]


def _nuclei_public_state(scan_id: str) -> dict:
    with _nuclei_lock:
        state = dict(_nuclei_state.get(scan_id) or {})
        if not state:
            return {}
        state.pop("process", None)
        state.pop("hosts", None)
        state["logs"] = list(state.get("logs") or [])
        state["findings"] = list(state.get("findings") or [])
        state["findings_total"] = len(state["findings"])
        return state


def _nuclei_append_log(scan_id: str, line: str, stream: str = "stdout"):
    text = (line or "").strip()
    if not text:
        return
    entry = {"ts": db.now(), "stream": stream, "line": text[:1200]}
    with _nuclei_lock:
        state = _nuclei_state.get(scan_id)
        if not state:
            return
        logs = state.setdefault("logs", [])
        logs.append(entry)
        if len(logs) > NUCLEI_LOG_BUFFER:
            del logs[:-NUCLEI_LOG_BUFFER]
        payload = _nuclei_public_state_locked(scan_id)
    broadcast("nuclei_log", {"id": scan_id, "entry": entry})
    broadcast("nuclei_update", payload)


def _nuclei_public_state_locked(scan_id: str) -> dict:
    state = dict(_nuclei_state.get(scan_id) or {})
    state.pop("process", None)
    state.pop("hosts", None)
    state["logs"] = list(state.get("logs") or [])
    state["findings"] = list(state.get("findings") or [])
    state["findings_total"] = len(state["findings"])
    return state


def _nuclei_set_state(scan_id: str, **updates) -> dict:
    with _nuclei_lock:
        state = _nuclei_state.get(scan_id)
        if not state:
            return {}
        state.update(updates)
        payload = _nuclei_public_state_locked(scan_id)
    broadcast("nuclei_update", payload)
    return payload


def _nuclei_active_statuses() -> set[str]:
    return {"queued", "preparing", "running", "paused", "stopping"}


def _nuclei_log_status(scan_id: str, message: str, **updates) -> dict:
    payload = _nuclei_set_state(scan_id, message=message, **updates)
    _nuclei_append_log(scan_id, message, stream="status")
    return payload


def _nuclei_scan_sort_key(state: dict) -> str:
    return str(state.get("started_at") or state.get("finished_at") or "")


def _nuclei_list_public(project_id: str | None = None, limit: int = 20, active_only: bool = False) -> list[dict]:
    with _nuclei_lock:
        states = list(_nuclei_state.values())
        if project_id:
            states = [s for s in states if s.get("project_id") == project_id]
        if active_only:
            active = _nuclei_active_statuses()
            states = [s for s in states if s.get("status") in active]
        states.sort(key=_nuclei_scan_sort_key, reverse=True)
        ids = [s.get("id") for s in states[:limit] if s.get("id")]
        return [_nuclei_public_state_locked(scan_id) for scan_id in ids]


def _run_nuclei_sync(pid: str, project_name: str, mode: str, hosts: list[str]) -> tuple[dict | None, str | None, int]:
    targets_file = ""
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(hosts) + "\n")
            targets_file = tf.name

        nuclei_bin = _resolve_nuclei_binary()
        if not nuclei_bin:
            return None, "nuclei binary not found in PATH, NUCLEI_BIN, /root/go/bin/nuclei, /usr/local/bin/nuclei, or /usr/bin/nuclei", 400
        templates_ok, templates_msg = _ensure_nuclei_templates(nuclei_bin)
        if not templates_ok:
            return None, templates_msg, 400

        templates_dir = _nuclei_templates_dir()
        cmd = _nuclei_command(nuclei_bin, targets_file, templates_dir)
        run = subprocess.run(cmd, text=True, capture_output=True, timeout=900)

        findings = []
        parse_errors = 0
        for ln in (run.stdout or "").splitlines():
            ln = ln.strip()
            if not ln or not ln.startswith("{"):
                continue
            try:
                findings.append(_normalize_nuclei_finding(json.loads(ln)))
            except Exception:
                parse_errors += 1

        stderr_tail = (run.stderr or "")[-4000:]
        stdout_tail = (run.stdout or "")[-4000:]
        if run.returncode != 0 and not findings:
            detail = stderr_tail or stdout_tail or f"nuclei exited with code {run.returncode}"
            return None, f"Nuclei scan failed: {detail}", 500

        return {
            "project_id": pid,
            "project_name": project_name,
            "scan_mode": mode,
            "hosts_scanned": len(hosts),
            "severities": ["medium", "high", "critical"],
            "command": "nuclei -l <hosts_file> -severity medium,high,critical -jsonl -stats -duc -ud <templates_dir> -t <templates_dir>",
            "findings": findings,
            "findings_total": len(findings),
            "stderr": stderr_tail,
            "exit_code": run.returncode,
            "parse_errors": parse_errors,
            "templates_status": templates_msg,
        }, None, 200
    except subprocess.TimeoutExpired:
        return None, "Nuclei scan timed out after 900s", 504
    except FileNotFoundError:
        return None, "nuclei binary not found", 400
    except Exception as e:
        return None, f"Nuclei scan failed: {e}", 500
    finally:
        if targets_file:
            try:
                os.unlink(targets_file)
            except OSError:
                pass


def _nuclei_worker(scan_id: str):
    targets_file = ""
    started = time.time()
    try:
        _nuclei_log_status(scan_id, "Preparing nuclei target file and template directory", status="preparing")
        with _nuclei_lock:
            state = _nuclei_state.get(scan_id) or {}
            hosts = list(state.get("hosts") or [])
            pid = state.get("project_id")
            project_name = state.get("project_name")
            mode = state.get("scan_mode")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(hosts) + "\n")
            targets_file = tf.name

        nuclei_bin = _resolve_nuclei_binary()
        if not nuclei_bin:
            _nuclei_log_status(scan_id, "Nuclei binary was not found; install nuclei or set NUCLEI_BIN", status="error", error="nuclei binary not found in PATH, NUCLEI_BIN, /root/go/bin/nuclei, /usr/local/bin/nuclei, or /usr/bin/nuclei", finished_at=db.now())
            return
        templates_ok, templates_msg = _ensure_nuclei_templates(nuclei_bin)
        if not templates_ok:
            _nuclei_log_status(scan_id, f"Template preparation failed: {templates_msg}", status="error", error=templates_msg, templates_status=templates_msg, finished_at=db.now())
            return

        templates_dir = _nuclei_templates_dir()
        with _nuclei_lock:
            stopped_before_start = bool((_nuclei_state.get(scan_id) or {}).get("stop_requested"))
        if stopped_before_start:
            _nuclei_log_status(scan_id, "Nuclei scan stopped before process start", status="stopped", finished_at=db.now())
            return
        cmd = _nuclei_command(nuclei_bin, targets_file, templates_dir)
        _nuclei_append_log(scan_id, f"Binary: {nuclei_bin}", stream="status")
        _nuclei_append_log(scan_id, f"Templates: {templates_dir} ({templates_msg})", stream="status")
        _nuclei_append_log(scan_id, f"Targets: {len(hosts)} host(s); mode={mode}; severities=medium,high,critical", stream="status")
        _nuclei_append_log(scan_id, "Command: nuclei -l <hosts_file> -severity medium,high,critical -jsonl -stats -duc -ud <templates_dir> -t <templates_dir>", stream="status")
        _nuclei_set_state(scan_id, status="running", message="Nuclei process is starting", templates_status=templates_msg, command=" ".join(cmd))
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )
        _nuclei_set_state(scan_id, process=process, process_id=process.pid, message=f"Nuclei process started (PID {process.pid})")
        _nuclei_append_log(scan_id, f"Process started with PID {process.pid}; streaming output below", stream="status")
        heartbeat_stop = threading.Event()

        def heartbeat():
            while not heartbeat_stop.wait(10):
                with _nuclei_lock:
                    state = _nuclei_state.get(scan_id) or {}
                    if state.get("status") not in {"running", "paused"}:
                        return
                    findings_count = len(state.get("findings") or [])
                    current_status = state.get("status") or "running"
                elapsed_hb = max(0, int(time.time() - started))
                _nuclei_append_log(scan_id, f"Still {current_status}: elapsed {elapsed_hb}s, findings {findings_count}, waiting for next nuclei event", stream="heartbeat")

        heartbeat_thread = threading.Thread(target=heartbeat, daemon=True, name=f"nuclei-heartbeat-{scan_id[:8]}")
        heartbeat_thread.start()
        parse_errors = 0
        assert process.stdout is not None
        for raw in process.stdout:
            line = raw.strip()
            if not line:
                continue
            parsed_finding = None
            if line.startswith("{"):
                try:
                    parsed_finding = _normalize_nuclei_finding(json.loads(line))
                except Exception:
                    parse_errors += 1
            if parsed_finding:
                with _nuclei_lock:
                    state = _nuclei_state.get(scan_id)
                    if state:
                        state.setdefault("findings", []).append(parsed_finding)
                        state["parse_errors"] = parse_errors
                        state["last_finding_at"] = db.now()
                        payload = _nuclei_public_state_locked(scan_id)
                    else:
                        payload = {}
                broadcast("nuclei_finding", {"id": scan_id, "finding": parsed_finding})
                if payload:
                    broadcast("nuclei_update", payload)
            _nuclei_append_log(scan_id, line)
        heartbeat_stop.set()
        exit_code = process.wait(timeout=10)
        elapsed = max(0, int(time.time() - started))
        with _nuclei_lock:
            state = _nuclei_state.get(scan_id) or {}
            stopped = bool(state.get("stop_requested"))
            findings = list(state.get("findings") or [])
        if stopped:
            _nuclei_log_status(scan_id, "Nuclei scan stopped", status="stopped", exit_code=exit_code, finished_at=db.now(), elapsed_seconds=elapsed)
        elif exit_code != 0 and not findings:
            _nuclei_log_status(scan_id, f"Nuclei exited with code {exit_code} and no findings", status="error", exit_code=exit_code, finished_at=db.now(), elapsed_seconds=elapsed, error=f"nuclei exited with code {exit_code}")
        else:
            _nuclei_log_status(scan_id, f"Nuclei scan complete: {len(findings)} finding(s), exit code {exit_code}", status="done", exit_code=exit_code, finished_at=db.now(), elapsed_seconds=elapsed)
    except Exception as e:
        _nuclei_log_status(scan_id, f"Nuclei scan failed: {e}", status="error", error=f"Nuclei scan failed: {e}", finished_at=db.now())
    finally:
        if targets_file:
            try:
                os.unlink(targets_file)
            except OSError:
                pass
        with _nuclei_lock:
            state = _nuclei_state.get(scan_id)
            if state:
                state.pop("process", None)
            _nuclei_threads.pop(scan_id, None)


def _start_nuclei_scan(pid: str, project_name: str, mode: str, hosts: list[str]) -> dict:
    scan_id = db.uid()
    total = len(hosts)
    estimate_seconds = max(30, min(3600, total * 3))
    now = db.now()
    with _nuclei_lock:
        for existing in _nuclei_state.values():
            if existing.get("project_id") == pid and existing.get("status") in _nuclei_active_statuses():
                raise RuntimeError("A nuclei scan is already running for this project")
        _nuclei_state[scan_id] = {
            "id": scan_id,
            "project_id": pid,
            "project_name": project_name,
            "scan_mode": mode,
            "status": "queued",
            "message": "Nuclei scan queued",
            "hosts_scanned": total,
            "total": total,
            "severities": ["medium", "high", "critical"],
            "estimated_seconds": estimate_seconds,
            "estimated_completion_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + estimate_seconds)),
            "started_at": now,
            "findings": [],
            "findings_total": 0,
            "parse_errors": 0,
            "logs": [],
            "hosts": hosts,
        }
    thread = threading.Thread(target=_nuclei_worker, args=(scan_id,), daemon=True, name=f"nuclei-scan-{scan_id[:8]}")
    with _nuclei_lock:
        _nuclei_threads[scan_id] = thread
    thread.start()
    payload = _nuclei_public_state(scan_id)
    broadcast("nuclei_update", payload)
    return payload


@api.post("/projects/<pid>/nuclei/scan")
def nuclei_scan_hosts(pid):
    p = db.project_get(pid)
    if not p:
        return err("Project not found", 404)

    mode = (request.args.get("mode", "latest_discoveries") or "latest_discoveries").strip().lower()
    if mode not in {"latest_discoveries", "all_subdomains"}:
        return err("Invalid mode. Use latest_discoveries or all_subdomains", 400)

    hosts = _resolve_nuclei_hosts(pid, mode)
    if not hosts:
        if mode == "all_subdomains":
            return err("No subdomains found for this project", 400)
        return err("No newly discovered hosts found for this project", 400)

    if (request.args.get("wait") or "").strip().lower() in {"1", "true", "yes"}:
        data, error_msg, code = _run_nuclei_sync(pid, p["name"], mode, hosts)
        if error_msg:
            return err(error_msg, code)
        return ok(data)

    try:
        payload = _start_nuclei_scan(pid, p["name"], mode, hosts)
    except RuntimeError as e:
        return err(str(e), 409)
    return ok({**payload, "message": f"Nuclei scan started for {len(hosts)} targets"})


@api.get("/nuclei/scans")
def nuclei_scans_list():
    project_id = (request.args.get("project_id") or "").strip() or None
    limit = _safe_int(request.args.get("limit", 20), 20, min_value=1, max_value=100)
    active_only = (request.args.get("active") or "").strip().lower() in {"1", "true", "yes"}
    return ok({"rows": _nuclei_list_public(project_id=project_id, limit=limit, active_only=active_only)})


@api.get("/nuclei/scans/<scan_id>")
def nuclei_scan_status(scan_id):
    state = _nuclei_public_state(scan_id)
    if not state:
        return err("Nuclei scan not found", 404)
    return ok(state)


@api.post("/nuclei/scans/<scan_id>/pause")
def pause_nuclei_scan(scan_id):
    with _nuclei_lock:
        state = _nuclei_state.get(scan_id)
        process = state.get("process") if state else None
        if not state:
            return err("Nuclei scan not found", 404)
        if state.get("status") != "running" or not process:
            return err("Nuclei scan is not running", 409)
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGSTOP)
    except Exception:
        process.send_signal(signal.SIGSTOP)
    return ok(_nuclei_set_state(scan_id, status="paused", message="Nuclei scan paused"))


@api.post("/nuclei/scans/<scan_id>/resume")
def resume_nuclei_scan(scan_id):
    with _nuclei_lock:
        state = _nuclei_state.get(scan_id)
        process = state.get("process") if state else None
        if not state:
            return err("Nuclei scan not found", 404)
        if state.get("status") != "paused" or not process:
            return err("Nuclei scan is not paused", 409)
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGCONT)
    except Exception:
        process.send_signal(signal.SIGCONT)
    return ok(_nuclei_set_state(scan_id, status="running", message="Nuclei scan resumed"))


@api.post("/nuclei/scans/<scan_id>/stop")
def stop_nuclei_scan(scan_id):
    with _nuclei_lock:
        state = _nuclei_state.get(scan_id)
        process = state.get("process") if state else None
        if not state:
            return err("Nuclei scan not found", 404)
        if state.get("status") not in {"queued", "preparing", "running", "paused"}:
            return err("Nuclei scan is not active", 409)
        state["stop_requested"] = True
    if process:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except Exception:
            process.terminate()
    return ok(_nuclei_set_state(scan_id, status="stopping", message="Stopping nuclei scan"))


@api.post("/projects/<pid>/nuclei/scan-new-discoveries")
def nuclei_scan_new_discoveries(pid):
    return nuclei_scan_hosts(pid)
@api.post("/projects/<pid>/openssl")
def openssl_subjects(pid):
    p = db.project_get(pid)
    if not p:
        return err("Project not found", 404)

    # Keep this endpoint side-effect free: it reports certificate subjects for
    # already authorized inventory instead of launching hidden enumeration first.
    subfinder_job_id = None
    subfinder_error = ""
    hosts = _collect_openssl_hosts(pid)
    if not hosts:
        return err("No hosts found. Upload project hosts first.", 400)

    rows = [_run_openssl_subject(h) for h in hosts]
    db.openssl_results_upsert_batch(pid, rows, source="manual")
    return ok({
        "project_id": pid,
        "project_name": p["name"],
        "hosts_total": len(hosts),
        "subfinder_job_id": subfinder_job_id,
        "subfinder_error": subfinder_error,
        "command_template": "openssl s_client -connect HOSTNAME:443 </dev/null 2>/dev/null | grep subject",
        "rows": rows,
    })


@api.get("/projects/<pid>/openssl")
def openssl_subjects_list(pid):
    p = db.project_get(pid)
    if not p:
        return err("Project not found", 404)
    limit = _safe_int(request.args.get("limit", 2000), 2000, min_value=50, max_value=5000)
    search = (request.args.get("search", "") or "").strip()
    rows = db.openssl_results_list(pid, search=search, limit=limit)
    with _openssl_lock:
        status = dict(_openssl_status.get(pid) or {"status": "idle"})
    return ok({
        "project_id": pid,
        "project_name": p["name"],
        "rows": rows,
        "rows_total": len(rows),
        "tracked_hosts": len(_collect_openssl_hosts(pid)),
        "worker": status,
    })


@api.post("/projects/<pid>/openssl/start")
def openssl_subjects_start(pid):
    p = db.project_get(pid)
    if not p:
        return err("Project not found", 404)
    started = _start_openssl_worker(pid, source="continuous")
    return ok({
        "project_id": pid,
        "project_name": p["name"],
        "started": started,
        "message": "OpenSSL continuous scan started" if started else "OpenSSL continuous scan already running",
    })


# ── Background SSE broadcaster for scan progress ───────────────────────────────

def _scan_broadcast_loop():
    """Pushes scan progress and stats via SSE every 3 seconds if anyone is scanning."""
    while True:
        try:
            active = list_active_scans()
            if active:
                for s in active:
                    broadcast("scan_update", s)
                # Also push updated stats
                broadcast("stats_update", db.stats_global())
                # Push alert count
                broadcast("alert_update", {"unseen_count": db.alerts_unseen_count()})
        except Exception:
            pass
        time.sleep(3)


threading.Thread(target=_scan_broadcast_loop, daemon=True, name="sse-broadcaster").start()
