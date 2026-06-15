from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

import db.database as db


def _reset_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "sentinel.db")
    if getattr(db._local, "c", None):
        db._local.c.close()
        db._local.c = None
    db.init_db()


def test_domain_enum_results_merge_sources_for_same_hostname(tmp_path, monkeypatch):
    _reset_db(tmp_path, monkeypatch)
    scan_id = db.domain_enum_scan_create("example.com")

    db.domain_enum_results_add_batch(scan_id, "example.com", ["api.example.com", "www.example.com"], source="subfinder")
    db.domain_enum_results_add_batch(scan_id, "example.com", ["api.example.com"], source="crtsh")
    db.domain_enum_results_add_batch(scan_id, "example.com", ["api.example.com"], source="subfinder")

    rows = {row["hostname"]: row for row in db.domain_enum_results_by_scan(scan_id)}

    assert rows["api.example.com"]["source"] == "subfinder,crtsh"
    assert rows["www.example.com"]["source"] == "subfinder"
