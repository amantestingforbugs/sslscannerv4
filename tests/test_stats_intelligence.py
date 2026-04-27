from pathlib import Path
import sys
import threading

sys.path.append(str(Path(__file__).resolve().parents[1]))

import db.database as db


def _reset_conn_for_test():
    db._local = threading.local()


def test_stats_intelligence_returns_zero_state_for_empty_db(tmp_path):
    db.DB_PATH = tmp_path / "sentinel-test-empty.db"
    _reset_conn_for_test()
    db.init_db()

    data = db.stats_intelligence(scan_window=14)
    assert data["risk_score"] == 0
    assert data["risk_label"] == "healthy"
    assert data["trend_points"] == []
    assert data["top_risky_projects"] == []


def test_stats_intelligence_identifies_risky_projects(tmp_path):
    db.DB_PATH = tmp_path / "sentinel-test-risk.db"
    _reset_conn_for_test()
    db.init_db()

    p1 = db.project_create("alpha")
    p2 = db.project_create("beta")

    sid1 = db.scan_create(p1["id"], total=10)
    db.scan_update(
        sid1["id"],
        status="done",
        done=10,
        mismatches=2,
        expired=1,
        expiring=1,
        errors=0,
        ok=6,
        finished_at=db.now(),
    )

    sid2 = db.scan_create(p2["id"], total=10)
    db.scan_update(
        sid2["id"],
        status="done",
        done=10,
        mismatches=0,
        expired=0,
        expiring=0,
        errors=0,
        ok=10,
        finished_at=db.now(),
    )

    data = db.stats_intelligence(scan_window=14)

    assert data["risk_score"] > 0
    assert len(data["trend_points"]) == 2
    assert data["top_risky_projects"][0]["project_name"] == "alpha"
    assert data["top_risky_projects"][0]["risk_score"] > data["top_risky_projects"][1]["risk_score"]
