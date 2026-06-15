from pathlib import Path
import importlib
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from core.risk_engine import score_asset


def reset_db(tmp_path, monkeypatch):
    db = importlib.import_module("db.database")
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "sentinel.db")
    if getattr(db._local, "c", None):
        db._local.c.close()
        db._local.c = None
    db.init_db()
    return db


def test_score_asset_weights_exposure_tls_http_freshness_and_context():
    result = score_asset(
        {"hostname": "admin-api.example.com", "internet_exposed": True, "is_latest_discovery": True},
        findings=[{"info": {"severity": "high"}}],
        observations={
            "http_status_code": 403,
            "http_page_title": "Swagger Admin Login",
            "is_mismatch": 1,
            "key_bits": 1024,
            "tls_version": "TLSv1.0",
            "cipher_suite": "ECDHE-RSA-3DES-SHA",
        },
        context={"criticality": "critical", "owner": "payments"},
    )

    assert result["score"] >= 75
    assert result["severity"] == "critical"
    assert any("Nuclei" in e for e in result["evidence"])
    assert any(f["name"] == "tls_mismatch" for f in result["factors"])


def test_risk_api_scores_assets_and_persists_rows(tmp_path, monkeypatch):
    db = reset_db(tmp_path, monkeypatch)
    routes = importlib.import_module("api.routes")
    routes.db = db

    project = db.project_create("risk-program")
    job_id = db.subfinder_job_create(project["id"], "example.com", by="manual")
    db.subfinder_hosts_add_batch(project["id"], ["admin.example.com", "www.example.com"])
    db.subfinder_new_discoveries_add_batch(job_id, project["id"], ["admin.example.com"])
    db.subfinder_httpx_results_upsert_batch(project["id"], job_id, [
        {"hostname": "admin.example.com", "status_code": 403, "page_title": "Admin Login", "final_url": "https://admin.example.com", "scheme": "https", "is_active": True},
        {"hostname": "www.example.com", "status_code": 200, "page_title": "Home", "final_url": "https://www.example.com", "scheme": "https", "is_active": True},
    ])
    scan = db.scan_create(project["id"], 2, "manual")
    db.results_batch_save(scan["id"], project["id"], [
        {"hostname": "admin.example.com", "is_mismatch": True, "key_bits": 1024, "tls_version": "TLSv1.0", "cipher_suite": "3DES"},
        {"hostname": "www.example.com", "is_ok": True, "key_bits": 2048, "tls_version": "TLSv1.3"},
    ])

    app = importlib.import_module("flask").Flask(__name__)
    app.register_blueprint(routes.api)
    client = app.test_client()

    assets = client.get("/api/risk/assets?limit=10").get_json()["data"]
    summary = client.get("/api/risk/summary").get_json()["data"]

    assert assets["rows"][0]["hostname"] == "admin.example.com"
    assert assets["rows"][0]["score"] > assets["rows"][1]["score"]
    assert summary["severity_distribution"]
    assert db.asset_risk_scores_list(limit=10)
