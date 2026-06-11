from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

import db.database as db
from api.routes import _collect_bounty_leads, _score_bounty_lead


def reset_db(tmp_path, monkeypatch):
    db_path = tmp_path / "sentinel.db"
    monkeypatch.setattr(db, "DB_PATH", db_path)
    if getattr(db._local, "c", None):
        db._local.c.close()
        db._local.c = None
    db.init_db()
    return db_path


def test_bounty_lead_scoring_prioritizes_active_admin_api_surfaces():
    row = {
        "hostname": "admin-api.dev.example.com",
        "http_status_code": 403,
        "http_page_title": "Swagger Admin Login",
        "http_final_url": "https://admin-api.dev.example.com/swagger",
        "http_is_active": 1,
        "is_latest_discovery": 1,
        "is_mismatch": 1,
    }

    lead = _score_bounty_lead(row)

    assert lead["score"] >= 75
    assert lead["severity"] == "high"
    assert "API" in lead["lead_type"] or "Admin" in lead["lead_type"]
    assert any("authorized bug-bounty scope" in step for step in lead["next_steps"])


def test_collect_bounty_leads_returns_ranked_authorized_discoveries(tmp_path, monkeypatch):
    reset_db(tmp_path, monkeypatch)
    project = db.project_create("bounty-program")
    job_id = db.subfinder_job_create(project["id"], "example.com", by="manual")
    db.subfinder_hosts_add_batch(project["id"], ["admin-api.dev.example.com", "cdn.example.com"])
    db.subfinder_new_discoveries_add_batch(job_id, project["id"], ["admin-api.dev.example.com"])
    db.subfinder_httpx_results_upsert_batch(project["id"], job_id, [
        {
            "hostname": "admin-api.dev.example.com",
            "status_code": 403,
            "page_title": "Swagger Admin Login",
            "final_url": "https://admin-api.dev.example.com/swagger",
            "scheme": "https",
            "is_active": True,
        },
        {
            "hostname": "cdn.example.com",
            "status_code": 200,
            "page_title": "Static CDN",
            "final_url": "https://cdn.example.com/",
            "scheme": "https",
            "is_active": True,
        },
    ])
    scan = db.scan_create(project["id"], 1, "manual")
    db.results_batch_save(scan["id"], project["id"], [{
        "hostname": "admin-api.dev.example.com",
        "cn": "wrong.example.net",
        "sans": ["wrong.example.net"],
        "is_mismatch": True,
    }])

    data = _collect_bounty_leads(project_id=project["id"], limit=10)

    assert data["total"] == 2
    assert data["rows"][0]["hostname"] == "admin-api.dev.example.com"
    assert data["rows"][0]["score"] > data["rows"][1]["score"]
    assert "TLS hostname mismatch" in " ".join(data["rows"][0]["evidence"])
