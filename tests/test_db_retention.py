from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

import db.database as db


def test_scans_prune_older_than_7_days(tmp_path, monkeypatch):
    db_path = tmp_path / "sentinel.db"
    monkeypatch.setattr(db, "DB_PATH", db_path)

    if getattr(db._local, "c", None):
        db._local.c.close()
        db._local.c = None

    db.init_db()

    pid = db.uid()
    stale_scan = db.uid()
    fresh_scan = db.uid()
    now_val = db.now()

    db.x(
        "INSERT INTO projects(id,name,created_at,updated_at) VALUES(?,?,?,?)",
        (pid, "retention-project", now_val, now_val),
    )
    db.x(
        "INSERT INTO scans(id,project_id,status,total,done,created_at,started_at) VALUES(?,?,?,?,?,?,?)",
        (stale_scan, pid, "done", 1, 1, "2020-01-01T00:00:00+00:00", "2020-01-01T00:00:00+00:00"),
    )
    db.x(
        "INSERT INTO scans(id,project_id,status,total,done,created_at,started_at) VALUES(?,?,?,?,?,?,?)",
        (fresh_scan, pid, "done", 1, 1, now_val, now_val),
    )
    db.x(
        "INSERT INTO results(id,scan_id,project_id,hostname,checked_at) VALUES(?,?,?,?,?)",
        (db.uid(), stale_scan, pid, "old.example.com", "2020-01-01T00:00:00+00:00"),
    )
    db.x(
        "INSERT INTO results(id,scan_id,project_id,hostname,checked_at) VALUES(?,?,?,?,?)",
        (db.uid(), fresh_scan, pid, "new.example.com", now_val),
    )
    db.x(
        "INSERT INTO alerts(id,project_id,scan_id,hostname,issue_type,dedup_key,created_at) VALUES(?,?,?,?,?,?,?)",
        (db.uid(), pid, stale_scan, "old.example.com", "Expired", f"{pid}:old.example.com:Expired", "2020-01-01T00:00:00+00:00"),
    )
    db.commit()

    stats = db.scans_prune_older_than(days=7)

    assert stats["scans_deleted"] == 1
    assert db.x("SELECT COUNT(*) FROM scans WHERE id=?", (stale_scan,)).fetchone()[0] == 0
    assert db.x("SELECT COUNT(*) FROM scans WHERE id=?", (fresh_scan,)).fetchone()[0] == 1
    assert db.x("SELECT COUNT(*) FROM results WHERE scan_id=?", (stale_scan,)).fetchone()[0] == 0
    assert db.x("SELECT COUNT(*) FROM results WHERE scan_id=?", (fresh_scan,)).fetchone()[0] == 1
    assert db.x("SELECT COUNT(*) FROM alerts WHERE scan_id=?", (stale_scan,)).fetchone()[0] == 0
