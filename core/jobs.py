"""Durable job orchestration facade.

SQLite is the default backend.  The interface is intentionally small so a
Redis/Celery/RQ/Dramatiq/cloud-queue backend can implement the same methods and
let workers run outside the Flask process.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import db.database as db

ACTIVE_STATUSES = {"queued", "preparing", "running", "paused", "stopping"}
TERMINAL_STATUSES = {"done", "error", "stopped", "cancelled"}


class JobBackend(Protocol):
    def create_job(self, job_type: str, payload: dict[str, Any] | None = None, **fields) -> dict[str, Any]: ...
    def get_job(self, job_id: str) -> dict[str, Any] | None: ...
    def list_jobs(self, job_type: str | None = None, **filters) -> list[dict[str, Any]]: ...
    def update_job(self, job_id: str, **updates) -> dict[str, Any] | None: ...
    def append_event(self, job_id: str, event: str, data: dict[str, Any] | None = None) -> dict[str, Any]: ...
    def request_control(self, job_id: str, action: str, reason: str = "") -> bool: ...
    def get_control(self, job_id: str) -> dict[str, Any]: ...


@dataclass
class SQLiteJobBackend:
    """SQLite-backed implementation used by single-node/community deployments."""

    def create_job(self, job_type: str, payload: dict[str, Any] | None = None, **fields) -> dict[str, Any]:
        return db.job_create(job_type, payload=payload or {}, **fields)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        return db.job_get(job_id)

    def list_jobs(self, job_type: str | None = None, **filters) -> list[dict[str, Any]]:
        return db.job_list(job_type=job_type, **filters)

    def update_job(self, job_id: str, **updates) -> dict[str, Any] | None:
        return db.job_update(job_id, **updates)

    def append_event(self, job_id: str, event: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        return db.job_event_append(job_id, event, data or {})

    def request_control(self, job_id: str, action: str, reason: str = "") -> bool:
        return db.job_control_request(job_id, action, reason=reason)

    def get_control(self, job_id: str) -> dict[str, Any]:
        return db.job_control_get(job_id)


backend: JobBackend = SQLiteJobBackend()


def create_job(job_type: str, payload: dict[str, Any] | None = None, **fields) -> dict[str, Any]:
    job = backend.create_job(job_type, payload=payload, **fields)
    append_event(job["id"], f"{job_type}_created", public_state(job))
    return job


def get_job(job_id: str) -> dict[str, Any] | None:
    return backend.get_job(job_id)


def list_jobs(job_type: str | None = None, **filters) -> list[dict[str, Any]]:
    return backend.list_jobs(job_type=job_type, **filters)


def update_progress(job_id: str, *, done: int | None = None, total: int | None = None, progress: int | None = None, **payload_updates) -> dict[str, Any] | None:
    updates: dict[str, Any] = {}
    if done is not None:
        updates["done"] = done
        updates["progress"] = done if progress is None else progress
    if total is not None:
        updates["total"] = total
    if progress is not None:
        updates["progress"] = progress
    if payload_updates:
        job = get_job(job_id) or {}
        payload = dict(job.get("payload") or {})
        payload.update(payload_updates)
        updates["payload"] = payload
    job = backend.update_job(job_id, **updates)
    if job:
        append_event(job_id, f"{job['type']}_update", public_state(job))
    return job


def update_state(job_id: str, **updates) -> dict[str, Any] | None:
    if updates.get("status") in TERMINAL_STATUSES and not updates.get("finished_at"):
        updates["finished_at"] = db.now()
    job = backend.update_job(job_id, **updates)
    if job:
        append_event(job_id, f"{job['type']}_update", public_state(job))
    return job


def append_log(job_id: str, line: str, stream: str = "stdout") -> dict[str, Any]:
    return append_event(job_id, "job_log", {"id": job_id, "stream": stream, "line": line, "ts": db.now()})


def append_event(job_id: str, event: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    return backend.append_event(job_id, event, data or {})


def events_since(last_id: int = 0, limit: int = 100) -> list[dict[str, Any]]:
    return db.job_events_since(last_id, limit=limit)


def request_pause(job_id: str) -> bool: return backend.request_control(job_id, "pause")
def request_resume(job_id: str) -> bool: return backend.request_control(job_id, "resume")
def request_cancel(job_id: str) -> bool: return backend.request_control(job_id, "cancel")
def get_control(job_id: str) -> dict[str, Any]: return backend.get_control(job_id)


def public_state(job: dict[str, Any] | None) -> dict[str, Any]:
    if not job:
        return {}
    payload = dict(job.get("payload") or {})
    hidden = {"hosts", "process"}
    payload = {k: v for k, v in payload.items() if k not in hidden}
    return {**payload, **{k: v for k, v in job.items() if k != "payload"}}
