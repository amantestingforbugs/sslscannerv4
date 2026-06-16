from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (ROOT / "templates" / "index.html").read_text()


def _input_attrs(element_id: str) -> dict[str, str]:
    match = re.search(rf'<input\b[^>]*\bid="{re.escape(element_id)}"[^>]*>', TEMPLATE)
    assert match, f"missing input #{element_id}"
    return dict(re.findall(r'([\w-]+)="([^"]*)"', match.group(0)))


def test_project_interval_controls_match_backend_limits():
    """Project forms should expose the same interval range accepted by routes.py."""
    for element_id in ("cp-scan-int", "cp-sf-int", "ep-scan-int", "ep-sf-int"):
        attrs = _input_attrs(element_id)
        assert attrs["min"] == "5"
        assert attrs["max"] == "10080"


def test_subfinder_interval_hint_matches_backend_limits():
    assert "Discovery interval (5–10080 minutes)" in TEMPLATE
    assert "Discovery interval (10–30 minutes)" not in TEMPLATE


def test_project_interval_persistence_matches_ui_contract(tmp_path, monkeypatch):
    """Database project helpers should preserve the interval range shown in the UI."""
    sys.path.insert(0, str(ROOT))
    import db.database as database

    monkeypatch.setattr(database, "DB_PATH", tmp_path / "contract.sqlite3")
    monkeypatch.setattr(database, "_local", __import__("threading").local())
    database.init_db()

    project = database.project_create("wide-interval", scan_interval=5, subfinder_interval=10080)
    assert project["scan_interval_minutes"] == 5
    assert project["subfinder_interval_minutes"] == 10080

    database.project_update(project["id"], scan_interval_minutes=10080, subfinder_interval_minutes=5)
    updated = database.project_get(project["id"])
    assert updated["scan_interval_minutes"] == 10080
    assert updated["subfinder_interval_minutes"] == 5


def test_dashboard_replaces_hunter_mission_board_with_ai_copilot():
    assert "Bug Bounty Launchpad" not in TEMPLATE
    assert "Hunter mission board" not in TEMPLATE
    assert "AI Bounty Copilot" in TEMPLATE
    assert "Prompt workbench" in TEMPLATE
    assert "AI prompt pack" in TEMPLATE
    assert "Actionable bounty copilot" in TEMPLATE
    assert "/api/bounty/copilot" in TEMPLATE


def test_project_create_duplicate_returns_json_error(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT))
    from flask import Flask
    import db.database as database
    import api.routes as routes

    monkeypatch.setattr(database, "DB_PATH", tmp_path / "projects_create.sqlite3")
    monkeypatch.setattr(database, "_local", __import__("threading").local())
    database.init_db()

    app = Flask(__name__)
    app.register_blueprint(routes.api)
    client = app.test_client()

    first = client.post("/api/projects", json={"name": "dupe"})
    duplicate = client.post("/api/projects", json={"name": "dupe"})

    assert first.status_code == 200
    assert duplicate.status_code == 400
    assert duplicate.is_json
    assert duplicate.json == {"ok": False, "error": "A project with that name already exists"}


def test_enumeration_project_creation_uses_available_name(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT))
    from flask import Flask
    import db.database as database
    import api.routes as routes

    monkeypatch.setattr(database, "DB_PATH", tmp_path / "enum_project.sqlite3")
    monkeypatch.setattr(database, "_local", __import__("threading").local())
    database.init_db()

    existing = database.project_create("Enum example.com")
    scan_id = database.domain_enum_scan_create("example.com")
    database.domain_enum_results_add_batch(scan_id, "example.com", ["www.example.com", "api.example.com"])
    database.domain_enum_scan_finish(scan_id, "done", 2)

    app = Flask(__name__)
    app.register_blueprint(routes.api)
    client = app.test_client()

    resp = client.post(f"/api/subfinder/enumeration/scans/{scan_id}/project", json={"name": "Enum example.com"})

    assert resp.status_code == 200
    assert resp.json["data"]["project"]["id"] != existing["id"]
    assert resp.json["data"]["project"]["name"] == "Enum example.com (2)"
    assert resp.json["data"]["host_count"] == 2
