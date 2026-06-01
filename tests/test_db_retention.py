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


def test_storage_prune_removes_subfinder_raw_history(tmp_path, monkeypatch):
    db_path = tmp_path / "sentinel.db"
    raw_path = tmp_path / "old_raw.json.gz"
    raw_path.write_text("old raw payload")
    monkeypatch.setattr(db, "DB_PATH", db_path)

    if getattr(db._local, "c", None):
        db._local.c.close()
        db._local.c = None

    db.init_db()

    pid = db.uid()
    job_id = db.uid()
    raw_id = db.uid()
    now_val = db.now()
    old_val = "2020-01-01T00:00:00+00:00"

    db.x(
        "INSERT INTO projects(id,name,created_at,updated_at) VALUES(?,?,?,?)",
        (pid, "raw-retention-project", now_val, now_val),
    )
    db.x(
        "INSERT INTO subfinder_jobs(id,project_id,started_at,raw_output_path) VALUES(?,?,?,?)",
        (job_id, pid, old_val, str(raw_path)),
    )
    db.x(
        "INSERT INTO subfinder_raw_results(id,job_id,project_id,root_domain,started_at) VALUES(?,?,?,?,?)",
        (raw_id, job_id, pid, "example.com", old_val),
    )
    db.x(
        "INSERT INTO subfinder_new_discoveries(id,job_id,project_id,hostname,discovered_at) VALUES(?,?,?,?,?)",
        (db.uid(), job_id, pid, "old.example.com", old_val),
    )
    db.commit()

    stats = db.storage_prune(scan_days=7, raw_days=2, vacuum=False)

    assert stats["subfinder_jobs_deleted"] == 1
    assert stats["subfinder_raw_results_deleted"] == 1
    assert stats["subfinder_discoveries_deleted"] == 1
    assert stats["subfinder_raw_files_deleted"] == 1
    assert not raw_path.exists()
    assert db.x("SELECT COUNT(*) FROM subfinder_jobs WHERE id=?", (job_id,)).fetchone()[0] == 0
    assert db.x("SELECT COUNT(*) FROM subfinder_raw_results WHERE id=?", (raw_id,)).fetchone()[0] == 0


def test_subfinder_raw_result_finish_stores_bounded_preview(tmp_path, monkeypatch):
    db_path = tmp_path / "sentinel.db"
    monkeypatch.setattr(db, "DB_PATH", db_path)
    monkeypatch.setenv("SUBFINDER_RAW_STDOUT_MAX_CHARS", "20")
    monkeypatch.setenv("SUBFINDER_RAW_STDERR_MAX_CHARS", "10")

    if getattr(db._local, "c", None):
        db._local.c.close()
        db._local.c = None

    db.init_db()

    pid = db.uid()
    job_id = db.uid()
    now_val = db.now()
    db.x(
        "INSERT INTO projects(id,name,created_at,updated_at) VALUES(?,?,?,?)",
        (pid, "raw-preview-project", now_val, now_val),
    )
    db.x(
        "INSERT INTO subfinder_jobs(id,project_id,started_at) VALUES(?,?,?)",
        (job_id, pid, now_val),
    )
    db.commit()

    raw_id = db.subfinder_raw_result_add(job_id, pid, "example.com", "subfinder example.com")
    db.subfinder_raw_result_finish(raw_id, "done", 0, 2, "a" * 100, "b" * 50)

    row = db.subfinder_raw_results_list(pid, limit=1, preview_chars=1000)[0]
    assert len(row["raw_preview"]) < 80
    assert "truncated" in row["raw_preview"]
    assert len(row["stderr_preview"]) < 70
    assert "truncated" in row["stderr_preview"]
