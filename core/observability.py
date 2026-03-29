from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable

_MAX_LOGS = 2000
_logs: deque[dict[str, Any]] = deque(maxlen=_MAX_LOGS)
_lock = threading.Lock()
_subscribers: list[Callable[[dict[str, Any]], None]] = []


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def subscribe(callback: Callable[[dict[str, Any]], None]) -> None:
    with _lock:
        _subscribers.append(callback)


def publish(event: str, payload: dict[str, Any]) -> None:
    data = {"event": event, **payload}
    with _lock:
        listeners = list(_subscribers)
    for cb in listeners:
        try:
            cb(data)
        except Exception:
            continue


def log_event(component: str, level: str, message: str, **meta: Any) -> dict[str, Any]:
    entry = {
        "timestamp": _now(),
        "component": component,
        "level": level.upper(),
        "message": message,
        **meta,
    }
    with _lock:
        _logs.append(entry)
    publish("log_update", {"entry": entry})
    return entry


def get_logs(limit: int = 200) -> list[dict[str, Any]]:
    cap = max(1, min(limit, _MAX_LOGS))
    with _lock:
        return list(_logs)[-cap:]
