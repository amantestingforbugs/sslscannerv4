import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def test_attack_surface_risk_endpoint_rolls_up_operational_posture(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    database = importlib.import_module("db.database")
    importlib.reload(database)
    database.init_db()

    routes = importlib.import_module("api.routes")
    routes.db = database

    project = database.project_create("Example Program", "", 60, 30)
    database.project_save_hosts(project["id"], ["www.example.com", "admin.example.com"])
    scan = database.scan_create(project["id"], 2, "manual")
    database.results_batch_save(scan["id"], project["id"], [
        {"hostname": "www.example.com", "is_ok": True},
        {"hostname": "admin.example.com", "is_mismatch": True, "cn": "other.example.net"},
    ])
    database.scan_finish(scan["id"])

    app = importlib.import_module("flask").Flask(__name__)
    app.register_blueprint(routes.api)
    response = app.test_client().get("/api/attack-surface/risk")

    assert response.status_code == 200
    payload = response.get_json()["data"]
    assert payload["risk_score"] > 0
    assert payload["posture"] in {"low", "moderate", "high", "critical"}
    assert payload["anomaly_count"] == 1
    assert payload["recommended_actions"]
    assert "bounty_summary" in payload
