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


def test_bounty_summary_rolls_up_company_attack_surface(tmp_path, monkeypatch):
    reset_db(tmp_path, monkeypatch)
    project = db.project_create("enterprise-program")
    job_id = db.subfinder_job_create(project["id"], "example.com", by="manual")
    db.subfinder_hosts_add_batch(project["id"], ["admin.example.com", "api.example.com", "www.example.com"])
    db.subfinder_new_discoveries_add_batch(job_id, project["id"], ["admin.example.com"])
    db.subfinder_httpx_results_upsert_batch(project["id"], job_id, [
        {"hostname": "admin.example.com", "status_code": 403, "page_title": "Admin Login", "final_url": "https://admin.example.com", "scheme": "https", "is_active": True},
        {"hostname": "api.example.com", "status_code": 200, "page_title": "OpenAPI Docs", "final_url": "https://api.example.com/docs", "scheme": "https", "is_active": True},
        {"hostname": "www.example.com", "status_code": 200, "page_title": "Home", "final_url": "https://www.example.com", "scheme": "https", "is_active": True},
    ])
    scan = db.scan_create(project["id"], 1, "manual")
    db.results_batch_save(scan["id"], project["id"], [{"hostname": "admin.example.com", "cn": "wrong.example.net", "is_mismatch": True}])

    from api.routes import _collect_bounty_summary
    summary = _collect_bounty_summary(project_id=project["id"])

    assert summary["total_leads"] == 3
    assert summary["active_http"] == 3
    assert summary["protected_http"] == 1
    assert summary["tls_anomalies"] == 1
    assert summary["top_surface_types"]
    assert "high-priority" in summary["executive_summary"]


def test_bounty_brief_builds_operator_plan_from_ranked_leads(tmp_path, monkeypatch):
    reset_db(tmp_path, monkeypatch)
    project = db.project_create("bounty-brief-program")
    job_id = db.subfinder_job_create(project["id"], "example.com", by="manual")
    db.subfinder_hosts_add_batch(project["id"], ["admin-api.staging.example.com", "www.example.com"])
    db.subfinder_new_discoveries_add_batch(job_id, project["id"], ["admin-api.staging.example.com"])
    db.subfinder_httpx_results_upsert_batch(project["id"], job_id, [
        {
            "hostname": "admin-api.staging.example.com",
            "status_code": 403,
            "page_title": "OpenAPI Admin Login",
            "final_url": "https://admin-api.staging.example.com/swagger",
            "scheme": "https",
            "is_active": True,
        },
        {
            "hostname": "www.example.com",
            "status_code": 200,
            "page_title": "Home",
            "final_url": "https://www.example.com",
            "scheme": "https",
            "is_active": True,
        },
    ])

    from api.routes import _collect_bounty_brief

    brief = _collect_bounty_brief(project_id=project["id"], limit=10)

    assert brief["critical_path"][0]["hostname"] == "admin-api.staging.example.com"
    assert brief["scope_guardrails"]
    hypothesis_ids = {h["id"] for h in brief["hypotheses"]}
    assert "access-control" in hypothesis_ids
    assert "api-exposure" in hypothesis_ids
    assert "environment-drift" in hypothesis_ids
    assert "Safe reproduction steps" in brief["report_template"]["sections"]
