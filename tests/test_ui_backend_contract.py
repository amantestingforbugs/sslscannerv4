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


def test_subfinder_job_history_shows_root_domains():
    assert "Root Domain(s)" in TEMPLATE
    assert "sfJobRootDomains(job)" in TEMPLATE
    assert "Enumeration Found" in TEMPLATE


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


def test_project_create_route_accepts_canonical_interval_fields(tmp_path, monkeypatch):
    """API clients should be able to send the same interval field names returned by the API."""
    sys.path.insert(0, str(ROOT))
    from flask import Flask
    import db.database as database
    import api.routes as routes

    monkeypatch.setattr(database, "DB_PATH", tmp_path / "projects_create_intervals.sqlite3")
    monkeypatch.setattr(database, "_local", __import__("threading").local())
    database.init_db()

    app = Flask(__name__)
    app.register_blueprint(routes.api)
    client = app.test_client()

    resp = client.post(
        "/api/projects",
        json={"name": "intervals", "scan_interval_minutes": 5, "subfinder_interval_minutes": 10080},
    )

    assert resp.status_code == 200
    assert resp.json["data"]["scan_interval_minutes"] == 5
    assert resp.json["data"]["subfinder_interval_minutes"] == 10080


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


def test_domain_enumeration_accepts_authorized_subdomain_scope(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT))
    from flask import Flask
    import db.database as database
    import api.routes as routes
    import subfinder.runner as runner

    monkeypatch.setattr(database, "DB_PATH", tmp_path / "enum_scoped.sqlite3")
    monkeypatch.setattr(database, "_local", __import__("threading").local())
    monkeypatch.setenv("SCAN_ALLOWED_DOMAINS", "portal.example.com")
    database.init_db()

    calls = []

    def fake_run(domain, triggered_by="manual", depth_mode="standard", verbose=False):
        calls.append({"domain": domain, "depth_mode": depth_mode})
        return {"scan_id": "scan1", "domain": domain, "total_found": 0, "verbose_log": []}

    monkeypatch.setattr(runner, "run_domain_enumeration_scan", fake_run)

    app = Flask(__name__)
    app.register_blueprint(routes.api)
    client = app.test_client()

    resp = client.post("/api/subfinder/enumeration/run", json={"domain": "portal.example.com"})

    assert resp.status_code == 200
    assert resp.json["ok"] is True
    assert calls == [{"domain": "example.com", "depth_mode": "standard"}]


def test_host_upload_accepts_multipart_files_and_raw_text(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT))
    from flask import Flask
    import io
    import db.database as database
    import api.routes as routes

    monkeypatch.setattr(database, "DB_PATH", tmp_path / "host_upload.sqlite3")
    monkeypatch.setattr(database, "_local", __import__("threading").local())
    monkeypatch.setattr(routes, "is_target_allowed", lambda host, check_dns=True: True)
    database.init_db()

    app = Flask(__name__)
    app.register_blueprint(routes.api)
    client = app.test_client()
    project = database.project_create("upload-hosts")

    multipart = client.post(
        f"/api/projects/{project['id']}/hosts",
        data={"file": (io.BytesIO(b"example.com\nhttps://api.example.com\n"), "hosts.list")},
        content_type="multipart/form-data",
    )
    assert multipart.status_code == 200
    assert multipart.json["data"]["count"] == 2
    assert database.project_hosts(project["id"]) == ["example.com", "api.example.com"]

    raw = client.post(
        f"/api/projects/{project['id']}/hosts",
        data="raw.example.com\n",
        content_type="text/plain",
    )
    assert raw.status_code == 200
    assert raw.json["data"]["count"] == 1
    assert database.project_hosts(project["id"]) == ["raw.example.com"]


def test_host_upload_does_not_wait_for_dns_resolution(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT))
    from flask import Flask
    import io
    import db.database as database
    import api.routes as routes

    monkeypatch.setattr(database, "DB_PATH", tmp_path / "host_upload_no_dns.sqlite3")
    monkeypatch.setattr(database, "_local", __import__("threading").local())

    def fail_dns(*args, **kwargs):
        raise AssertionError("host upload should not perform DNS resolution")

    routes.resolves_to_disallowed_ip.cache_clear()
    monkeypatch.setattr("core.target_policy.socket.getaddrinfo", fail_dns)
    database.init_db()

    app = Flask(__name__)
    app.register_blueprint(routes.api)
    client = app.test_client()
    project = database.project_create("upload-hosts-no-dns")

    resp = client.post(
        f"/api/projects/{project['id']}/hosts",
        data={"file": (io.BytesIO(b"one.example.com\ntwo.example.com\n"), "hosts.list")},
        content_type="multipart/form-data",
    )

    assert resp.status_code == 200
    assert resp.json["data"]["count"] == 2
    assert database.project_hosts(project["id"]) == ["one.example.com", "two.example.com"]


def test_host_upload_dropzone_uses_file_directly_when_datatransfer_is_unavailable():
    assert "async function uploadHostFile(file)" in TEMPLATE
    assert "if (f) uploadHostFile(f);" in TEMPLATE
    assert "input.value = '';" in TEMPLATE
    assert "function updateProjectHostCount(count)" in TEMPLATE
    assert "dropzone?.classList.add('is-uploading')" in TEMPLATE


def test_ui_api_client_supports_configurable_backend_and_api_key():
    assert "SSL_SENTINEL_API_BASE_URL" in TEMPLATE
    assert "ssl_sentinel_api_base_url" in TEMPLATE
    assert "ssl_sentinel_api_key" in TEMPLATE
    assert "function apiUrl(url)" in TEMPLATE
    assert "X-API-Key" in TEMPLATE
    assert "function parseApiResponse(resp)" in TEMPLATE
    assert "sseUrl.searchParams.set('api_key', API_KEY)" in TEMPLATE


def test_api_key_gate_accepts_sse_query_token(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT))
    from flask import Flask
    import db.database as database
    import api.routes as routes

    monkeypatch.setattr(database, "DB_PATH", tmp_path / "api_key.sqlite3")
    monkeypatch.setattr(database, "_local", __import__("threading").local())
    monkeypatch.setenv("API_REQUIRE_KEY", "true")
    monkeypatch.setenv("API_KEY", "secret")
    database.init_db()

    app = Flask(__name__)
    app.register_blueprint(routes.api)
    client = app.test_client()

    unauthorized = client.get("/api/projects")
    authorized_header = client.get("/api/projects", headers={"X-API-Key": "secret"})
    authorized_query = client.get("/api/projects?api_key=secret")

    assert unauthorized.status_code == 401
    assert authorized_header.status_code == 200
    assert authorized_query.status_code == 200


def test_domain_enumeration_request_does_not_pin_global_progress_bar():
    assert "const trackActivity = req.trackActivity !== false;" in TEMPLATE
    assert "trackActivity:false" in TEMPLATE
    assert "results will appear here automatically when the background scan completes" in TEMPLATE
    assert "button.textContent = '⏳ Enumerating…';" in TEMPLATE
    assert "async:true" in TEMPLATE
    assert "Enumeration is still running in the background" in TEMPLATE


def test_domain_enumeration_ui_defaults_to_standard_mode():
    assert '<option value="standard" selected>Standard (all passive sources)</option>' in TEMPLATE
    assert '<option value="aggressive">Aggressive (all sources + DNS expansion)</option>' in TEMPLATE
