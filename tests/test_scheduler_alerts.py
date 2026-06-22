from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from scheduler.runner import _build_alert_from_result


def test_build_alert_suppresses_ignored_scan_errors():
    result = {
        "hostname": "bad.example.com",
        "error": "Timeout",
        "is_ignored_error": True,
    }
    assert _build_alert_from_result(result, expiring_threshold=30) is None


def test_build_alert_keeps_non_ignored_scan_errors():
    result = {
        "hostname": "bad.example.com",
        "error": "certificate parse failure",
        "is_ignored_error": False,
    }
    alert = _build_alert_from_result(result, expiring_threshold=30)
    assert alert == ("bad.example.com", "Scan Error", "certificate parse failure", "")



def test_build_alert_honors_disabled_scan_error_rule():
    result = {
        "hostname": "bad.example.com",
        "error": "certificate parse failure",
        "is_ignored_error": False,
    }
    assert _build_alert_from_result(result, expiring_threshold=30, alert_settings={"rule_error": 0}) is None


def test_build_alert_honors_disabled_expiring_rule():
    result = {
        "hostname": "soon.example.com",
        "days_left": 10,
        "expiry": "2026-07-01",
        "is_ok": True,
    }
    assert _build_alert_from_result(result, expiring_threshold=30, alert_settings={"rule_expiring": 0}) is None


def test_prune_finished_scan_state_bounds_completed_entries(monkeypatch):
    import scheduler.runner as runner

    with runner._scan_lock:
        runner._scan_state.clear()
        runner._scan_state["active"] = {"status": "running", "start_ts": 1000.0}
        runner._scan_state["old"] = {"status": "done", "finished_ts": 1.0}
        runner._scan_state["recent"] = {"status": "done", "finished_ts": 995.0}

    monkeypatch.setattr(runner, "SCAN_STATE_TTL_SECONDS", 100)
    removed = runner.prune_finished_scan_state(now_ts=1000.0)

    assert removed == 1
    with runner._scan_lock:
        assert "old" not in runner._scan_state
        assert "recent" in runner._scan_state
        assert "active" in runner._scan_state
        runner._scan_state.clear()


def test_scheduler_limits_automatic_project_scan_starts(monkeypatch):
    import scheduler.runner as runner

    scheduler = runner.ContinuousScheduler()
    projects = [
        {"id": "p1", "enabled": 1, "scan_interval_minutes": 1},
        {"id": "p2", "enabled": 1, "scan_interval_minutes": 1},
    ]
    started = []

    monkeypatch.setattr(runner, "prune_finished_scan_state", lambda now_ts=None: 0)
    monkeypatch.setattr(runner, "active_ssl_scan_count", lambda: 0)
    monkeypatch.setattr(runner, "MAX_CONCURRENT_PROJECT_SCANS", 1)
    monkeypatch.setattr("db.database.storage_prune", lambda **kwargs: {})
    monkeypatch.setattr("db.database.project_list", lambda: projects)
    monkeypatch.setattr(runner, "run_project_scan_async", lambda pid, triggered_by="scheduler": started.append((pid, triggered_by)) or True)

    scheduler._last_retention_run = 1.0
    scheduler._tick()

    assert started == [("p1", "scheduler")]
    assert scheduler._last_run["p1"] > 0
    assert "p2" not in scheduler._last_run


def test_scheduler_waits_when_scan_capacity_is_full(monkeypatch):
    import scheduler.runner as runner

    scheduler = runner.ContinuousScheduler()
    started = []

    monkeypatch.setattr(runner, "prune_finished_scan_state", lambda now_ts=None: 0)
    monkeypatch.setattr(runner, "active_ssl_scan_count", lambda: 1)
    monkeypatch.setattr(runner, "MAX_CONCURRENT_PROJECT_SCANS", 1)
    monkeypatch.setattr("db.database.storage_prune", lambda **kwargs: {})
    monkeypatch.setattr("db.database.project_list", lambda: [{"id": "p1", "enabled": 1, "scan_interval_minutes": 1}])
    monkeypatch.setattr(runner, "run_project_scan_async", lambda pid, triggered_by="scheduler": started.append(pid) or True)

    scheduler._last_retention_run = 1.0
    scheduler._tick()

    assert started == []
    assert scheduler._last_run == {}
