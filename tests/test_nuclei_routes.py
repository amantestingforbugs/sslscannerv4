from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from api.routes import (  # noqa: E402
    _normalize_nuclei_finding,
    _normalize_nuclei_target,
    _resolve_nuclei_binary,
)


def test_normalize_nuclei_target_accepts_host_and_urls():
    assert _normalize_nuclei_target("Example.COM") == "example.com"
    assert _normalize_nuclei_target("https://Sub.Example.com:8443/path") == "sub.example.com"
    assert _normalize_nuclei_target("127.0.0.1") == ""
    assert _normalize_nuclei_target("not a host") == ""


def test_normalize_nuclei_finding_supports_jsonl_dash_keys():
    finding = _normalize_nuclei_finding({
        "template-id": "cves/2024/CVE-2024-test",
        "matched-at": "https://app.example.com/login",
        "info": {"severity": "HIGH", "name": "Example CVE"},
    })

    assert finding["template_id"] == "cves/2024/CVE-2024-test"
    assert finding["matched_at"] == "https://app.example.com/login"
    assert finding["host"] == "https://app.example.com/login"
    assert finding["info"]["severity"] == "high"


def test_resolve_nuclei_binary_prefers_configured_executable(tmp_path, monkeypatch):
    nuclei = tmp_path / "nuclei"
    nuclei.write_text("#!/bin/sh\nexit 0\n")
    nuclei.chmod(0o755)

    monkeypatch.setenv("NUCLEI_BIN", str(nuclei))
    monkeypatch.setenv("PATH", "")

    assert _resolve_nuclei_binary() == str(nuclei)


def test_nuclei_scan_route_runs_with_normalized_results_and_removes_targets(
    tmp_path, monkeypatch
):
    from flask import Flask
    import api.routes as routes

    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "sample.yaml").write_text("id: sample\n")
    nuclei = tmp_path / "nuclei"
    nuclei.write_text("#!/bin/sh\nexit 0\n")
    nuclei.chmod(0o755)
    captured = {}

    class FakeRun:
        returncode = 0
        stdout = (
            '{"template-id":"tpl-1","matched-at":"https://example.com",'
            '"info":{"severity":"medium","name":"Finding"}}\n'
        )
        stderr = ""

    def fake_run(cmd, text, capture_output, timeout):
        captured["cmd"] = cmd
        target_file = cmd[cmd.index("-l") + 1]
        captured["target_file"] = target_file
        captured["targets"] = Path(target_file).read_text().splitlines()
        return FakeRun()

    monkeypatch.setattr(routes.db, "project_get", lambda pid: {"id": pid, "name": "Project"})
    monkeypatch.setattr(routes.db, "project_hosts", lambda pid: ["HTTPS://Example.com/path", "localhost"])
    monkeypatch.setattr(routes.db, "x", lambda *a, **k: type("Rows", (), {"fetchall": lambda self: []})())
    monkeypatch.setenv("NUCLEI_BIN", str(nuclei))
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(template_dir))
    monkeypatch.setattr(routes.subprocess, "run", fake_run)

    app = Flask(__name__)
    app.register_blueprint(routes.api)

    response = app.test_client().post("/api/projects/p1/nuclei/scan?mode=all_subdomains&wait=1")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["ok"] is True
    assert payload["data"]["hosts_scanned"] == 1
    assert payload["data"]["findings"][0]["template_id"] == "tpl-1"
    assert captured["targets"] == ["example.com"]
    assert str(template_dir) in captured["cmd"]
    assert not Path(captured["target_file"]).exists()


def test_nuclei_scan_route_starts_async_scan(monkeypatch):
    from flask import Flask
    import api.routes as routes

    captured = {}

    def fake_start(pid, project_name, mode, hosts):
        captured.update({"pid": pid, "project_name": project_name, "mode": mode, "hosts": hosts})
        return {
            "id": "scan-1",
            "project_id": pid,
            "project_name": project_name,
            "scan_mode": mode,
            "status": "queued",
            "hosts_scanned": len(hosts),
            "estimated_seconds": 30,
            "estimated_completion_at": "2026-06-01T00:01:00Z",
            "findings": [],
            "findings_total": 0,
            "logs": [],
        }

    monkeypatch.setattr(routes.db, "project_get", lambda pid: {"id": pid, "name": "Project"})
    monkeypatch.setattr(routes, "_resolve_nuclei_hosts", lambda pid, mode: ["example.com"])
    monkeypatch.setattr(routes, "_start_nuclei_scan", fake_start)

    app = Flask(__name__)
    app.register_blueprint(routes.api)

    response = app.test_client().post("/api/projects/p1/nuclei/scan?mode=all_subdomains")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["ok"] is True
    assert payload["data"]["id"] == "scan-1"
    assert payload["data"]["status"] == "queued"
    assert "started" in payload["data"]["message"].lower()
    assert captured == {
        "pid": "p1",
        "project_name": "Project",
        "mode": "all_subdomains",
        "hosts": ["example.com"],
    }
