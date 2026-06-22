"""
scheduler/runner.py — Background SSL scan scheduler.
Exports BATCH_SIZE and PROGRESS_UPDATE_EVERY for use by subfinder module.
"""

import os
import threading, time, logging
from datetime import datetime, timezone
from typing import Dict, Optional
from core.observability import log_event, publish
from core import jobs

log = logging.getLogger(__name__)

# ── Shared constants (used by subfinder module too) ───────────────────────────
BATCH_SIZE = 500
PROGRESS_UPDATE_EVERY = 500
MAX_WORKERS = int(os.getenv("SSL_MAX_WORKERS", "50"))
SCAN_STATE_TTL_SECONDS = int(os.getenv("SCAN_STATE_TTL_SECONDS", "3600"))
SCAN_STATE_MAX_COMPLETED = int(os.getenv("SCAN_STATE_MAX_COMPLETED", "100"))
MAX_CONCURRENT_PROJECT_SCANS = max(1, int(os.getenv("MAX_CONCURRENT_PROJECT_SCANS", "1") or "1"))

# ── In-memory scan state (shared with subfinder via import) ───────────────────
_scan_state: Dict[str, Dict] = {}
_scan_lock = threading.Lock()
_scan_controls: Dict[str, Dict[str, threading.Event]] = {}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _build_alert_from_result(r: Dict, expiring_threshold: int):
    """
    Build an alert tuple from a scan result.
    Returns: (hostname, issue_type, details, mismatch_scope) or None.

    Mirrors original scanner behavior by suppressing noisy/expected
    connection failures (is_ignored_error).
    """
    hostname = r.get("hostname", "")
    days_left = r.get("days_left")
    is_expiring_by_setting = isinstance(days_left, int) and 0 <= days_left <= expiring_threshold

    # Keep derived flags aligned with the configured expiring threshold.
    if is_expiring_by_setting:
        r["is_expiring_soon"] = True
    elif r.get("is_expiring_soon") and isinstance(days_left, int) and days_left > expiring_threshold:
        r["is_expiring_soon"] = False
    if r.get("is_ok") and isinstance(days_left, int) and days_left <= expiring_threshold:
        r["is_ok"] = False

    if r.get("is_mismatch") and not r.get("error"):
        mismatch_scope = "same_domain" if r.get("same_base") else "different_domain"
        return (hostname, "SSL Mismatch", f"CN '{r.get('cn','?')}' ≠ hostname", mismatch_scope)
    if r.get("is_expired") and not r.get("error"):
        return (hostname, "Expired", f"Expired {r.get('expiry','?')}", "")
    if is_expiring_by_setting and not r.get("error"):
        return (hostname, "Expiring Soon", f"Expires {r.get('expiry','?')} ({r.get('days_left')}d)", "")
    if r.get("error") and not r.get("is_ignored_error"):
        return (hostname, "Scan Error", r.get("error") or "Unknown TLS error", "")
    return None


def get_scan_state(sid: str) -> Optional[Dict]:
    job = jobs.get_job(sid)
    return jobs.public_state(job) if job else None


def list_active_scans() -> list:
    return [jobs.public_state(j) for j in jobs.list_jobs(job_type="ssl_scan", active=True, limit=200)]


def active_ssl_scan_count() -> int:
    """Return the number of active project SSL scans across all projects."""
    return len(jobs.list_jobs(job_type="ssl_scan", active=True, limit=1000))


def prune_finished_scan_state(now_ts: Optional[float] = None) -> int:
    """Bound any legacy in-memory scan snapshots; durable jobs remain in SQLite."""
    now_ts = time.time() if now_ts is None else now_ts
    with _scan_lock:
        completed = [
            (sid, state)
            for sid, state in _scan_state.items()
            if state.get("status") in {"done", "error", "stopped", "cancelled"}
        ]
        stale_ids = {
            sid
            for sid, state in completed
            if now_ts - float(state.get("finished_ts") or state.get("start_ts") or 0) > SCAN_STATE_TTL_SECONDS
        }
        remaining = [(sid, state) for sid, state in completed if sid not in stale_ids]
        if len(remaining) > SCAN_STATE_MAX_COMPLETED:
            remaining.sort(key=lambda item: float(item[1].get("finished_ts") or item[1].get("start_ts") or 0))
            stale_ids.update(sid for sid, _ in remaining[: len(remaining) - SCAN_STATE_MAX_COMPLETED])
        for sid in stale_ids:
            _scan_state.pop(sid, None)
        return len(stale_ids)


def pause_scan(sid: str) -> bool:
    state = jobs.get_job(sid)
    return bool(state and state.get("status") == "running" and jobs.request_pause(sid))


def resume_scan(sid: str) -> bool:
    state = jobs.get_job(sid)
    return bool(state and state.get("status") == "paused" and jobs.request_resume(sid))


def stop_scan(sid: str) -> bool:
    state = jobs.get_job(sid)
    return bool(state and state.get("status") in {"running", "paused", "stopping"} and jobs.request_cancel(sid))


def run_project_scan(project_id: str, triggered_by: str = "manual") -> Optional[str]:
    from db.database import (
        project_get, project_hosts, scan_create, results_batch_save,
        scan_finish, scan_update, scan_progress,
        alert_add, alerts_unsent, alert_mark_sent, alerts_unseen_count, alert_settings_get,
        asset_backfill_project
    )
    from core.ssl_checker import run_checker
    from alerts.notifiers import AlertManager

    project = project_get(project_id)
    if not project:
        return None
    hosts = project_hosts(project_id)
    if not hosts:
        return None

    total = len(hosts)
    alert_settings = alert_settings_get()
    expiring_threshold = max(1, min(365, int(alert_settings.get("minimum_days_left") or 30)))
    log.info("Scan start: '%s' (%d hosts) [%s]", project["name"], total, triggered_by)
    log_event("ssl_scan", "info", "Scan started", project_id=project_id, total=total, triggered_by=triggered_by, status="running")

    scan = scan_create(project_id, total, triggered_by)
    sid = scan["id"]

    jobs.create_job("ssl_scan", id=sid, project_id=project_id, status="running", total=total, source=triggered_by, payload={"project_name": project["name"], "triggered_by": triggered_by})
    pause_event, stop_event = threading.Event(), threading.Event()

    def sync_controls():
        ctl = jobs.get_control(sid)
        if ctl.get("pause"):
            pause_event.set()
        else:
            pause_event.clear()
        if ctl.get("cancel"):
            stop_event.set(); pause_event.clear()

    result_batch, alert_batch, done_count = [], [], [0]
    lock = threading.Lock()

    def on_result(done, total_inner, r):
        alert = _build_alert_from_result(r, expiring_threshold)
        with lock:
            if alert:
                alert_batch.append(alert)
            result_batch.append(r)
            done_count[0] += 1
            cur = done_count[0]
            if len(result_batch) >= BATCH_SIZE:
                batch = result_batch[:]
                result_batch.clear()
                results_batch_save(sid, project_id, batch, backfill_assets=False)
                for h, issue, detail, scope in alert_batch:
                    alert_add(project_id, h, issue, detail, sid, mismatch_scope=scope)
                alert_batch.clear()
            if cur % PROGRESS_UPDATE_EVERY == 0:
                scan_progress(sid, cur)
                jobs.update_progress(sid, done=cur, total=total)
            sync_controls()

    try:
        run_checker(
            hosts,
            max_workers=MAX_WORKERS,
            progress_callback=on_result,
            collect_results=False,  # avoid storing millions of in-memory results
            pause_event=pause_event,
            stop_event=stop_event,
        )

        was_stopped = bool(stop_event.is_set() or jobs.get_control(sid).get("cancel"))

        with lock:
            if result_batch:
                results_batch_save(sid, project_id, result_batch, backfill_assets=False)
            for h, issue, detail, scope in alert_batch:
                alert_add(project_id, h, issue, detail, sid, mismatch_scope=scope)
        asset_backfill_project(project_id)
        publish("alert_update", {"unseen_count": alerts_unseen_count()})
        if was_stopped:
            done = done_count[0]
            scan_update(sid, status="stopped", finished_at=_now(), done=done)
            jobs.update_state(sid, status="stopped", progress=done, done=done, finished_at=_now())
            log_event("ssl_scan", "warning", "Scan stopped by user", project_id=project_id, scan_id=sid, total=total, done=done, status="stopped")
        else:
            scan_finish(sid)
            log_event("ssl_scan", "info", "Scan finished", project_id=project_id, scan_id=sid, total=total, status="idle")
            jobs.update_state(sid, status="done", progress=total, done=total, finished_at=_now())

        # Send remote alerts
        unsent = [a for a in alerts_unsent() if a["project_id"] == project_id]
        if unsent:
            manager = AlertManager(alert_settings_get())
            delivered = manager.dispatch(project["name"], unsent)
            if not delivered:
                log.warning("No remote alert channel accepted alerts for project '%s'; keeping alerts unsent for retry.", project["name"])
                return sid
            delivered_ids = set(manager.dispatchable_alert_ids(unsent))
            for a in unsent:
                if a["id"] in delivered_ids:
                    alert_mark_sent(a["id"])

        log.info("Scan done: '%s'", project["name"])
        return sid

    except Exception as e:
        log.exception("Scan failed for '%s': %s", project["name"], e)
        log_event("ssl_scan", "error", f"Scan failed: {e}", project_id=project_id, scan_id=sid, status="failed")
        scan_update(sid, status="error")
        jobs.update_state(sid, status="error", finished_at=_now())
        return None
    finally:
        pass


def run_project_scan_async(project_id: str, triggered_by: str = "manual") -> bool:
    for s in jobs.list_jobs(job_type="ssl_scan", project_id=project_id, active=True, limit=10):
        if s.get("status") in {"queued", "running", "paused", "stopping"}:
            return False
    threading.Thread(target=run_project_scan, args=(project_id, triggered_by),
                     daemon=True, name=f"scan-{project_id[:8]}").start()
    return True


class ContinuousScheduler:
    def __init__(self):
        self._thread = None
        self._stop = threading.Event()
        self._last_run: Dict[str, float] = {}
        self._last_retention_run = 0.0

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ssl-scheduler")
        self._thread.start()
        log.info("SSL scheduler started")

    def stop(self): self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            try: self._tick()
            except Exception as e: log.exception("Scheduler error: %s", e)
            self._stop.wait(60)

    def _tick(self):
        from db.database import project_list, storage_prune
        now_ts = time.time()
        pruned_state = prune_finished_scan_state(now_ts)
        if pruned_state:
            log.debug("Pruned %s completed scan states from memory", pruned_state)

        # Keep DB and raw-output growth bounded: run retention sweep once per day.
        if now_ts - self._last_retention_run >= 24 * 60 * 60:
            stats = storage_prune(
                scan_days=int(os.getenv("SCAN_RETENTION_DAYS", "7")),
                raw_days=int(os.getenv("RAW_RETENTION_DAYS", "2")),
                max_scans_per_project=int(os.getenv("MAX_SCANS_PER_PROJECT", "50")),
                max_domain_enum_scans=int(os.getenv("MAX_DOMAIN_ENUM_SCANS", "200")),
                vacuum=os.getenv("DB_VACUUM_AFTER_RETENTION", "1").strip().lower() not in {"0", "false", "no", "off"},
            )
            self._last_retention_run = now_ts
            deleted = sum(v for k, v in stats.items() if k.endswith("_deleted") and isinstance(v, int))
            if deleted:
                log.info("Storage retention cleanup complete: %s", stats)

        available_slots = max(0, MAX_CONCURRENT_PROJECT_SCANS - active_ssl_scan_count())
        if available_slots <= 0:
            return

        due_projects = []
        for p in project_list():
            if not p.get("enabled"):
                continue
            pid = p["id"]
            interval_s = p.get("scan_interval_minutes", 60) * 60
            if now_ts - self._last_run.get(pid, 0) >= interval_s:
                due_projects.append(p)

        # Large automatic scans can consume many sockets, worker threads, and
        # SQLite write bursts.  Start only a bounded number per scheduler tick
        # instead of launching every due project at once after boot or a long
        # sleep, which can exhaust small containers and crash the app.
        due_projects.sort(key=lambda p: self._last_run.get(p["id"], 0))
        for p in due_projects[:available_slots]:
            pid = p["id"]
            self._last_run[pid] = now_ts
            if not run_project_scan_async(pid, triggered_by="scheduler"):
                # If another worker won the race, let a future tick retry after
                # active capacity frees up instead of suppressing this project
                # for a full scan interval.
                self._last_run.pop(pid, None)


_scheduler = ContinuousScheduler()
def start_scheduler(): _scheduler.start()
def stop_scheduler():  _scheduler.stop()
