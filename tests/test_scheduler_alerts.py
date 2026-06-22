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
