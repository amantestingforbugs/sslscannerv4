from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from api.routes import (  # noqa: E402
    _ensure_nuclei_templates,
    _looks_like_nuclei_finding,
    _normalize_nuclei_finding,
    _normalize_nuclei_target,
    _nuclei_list_public,
    _nuclei_command,
    _nuclei_exit_error,
    _nuclei_supported_flags,
    _parse_nuclei_stats_line,
    _resolve_nuclei_binary,
)


def test_nuclei_command_uses_conservative_resource_limits(monkeypatch):
    monkeypatch.delenv("NUCLEI_RATE_LIMIT", raising=False)
    monkeypatch.delenv("NUCLEI_CONCURRENCY", raising=False)
    monkeypatch.delenv("NUCLEI_BULK_SIZE", raising=False)
    monkeypatch.delenv("NUCLEI_TIMEOUT", raising=False)

    cmd = _nuclei_command("/bin/nuclei", "/tmp/targets", "/tmp/templates")

    assert cmd[cmd.index("-rl") + 1] == "25"
    assert cmd[cmd.index("-c") + 1] == "10"
    assert cmd[cmd.index("-bs") + 1] == "10"
    assert cmd[cmd.index("-timeout") + 1] == "5"


def test_nuclei_command_omits_unsupported_optional_flags(monkeypatch):
    _nuclei_supported_flags.cache_clear()

    class FakeRun:
        stdout = "Usage of nuclei:\n  -l string\n  -jsonl\n  -stats\n  -t string\n  -rl int\n  -c int\n  -bs int\n  -timeout int\n"
        stderr = ""

    import api.routes as routes

    monkeypatch.setattr(routes.subprocess, "run", lambda *a, **k: FakeRun())

    cmd = _nuclei_command("/bin/nuclei", "/tmp/targets", "/tmp/templates")

    assert "-stats-json" not in cmd
    assert "-duc" not in cmd
    assert "-ud" not in cmd
    assert "-t" in cmd
    _nuclei_supported_flags.cache_clear()


def test_resolve_nuclei_binary_accepts_command_name_from_env(tmp_path, monkeypatch):
    import api.routes as routes

    nuclei = tmp_path / "nuclei"
    nuclei.write_text("#!/bin/sh\nexit 0\n")
    nuclei.chmod(0o755)

    monkeypatch.setenv("NUCLEI_BIN", "nuclei")
    monkeypatch.setenv("PATH", str(tmp_path))

    assert routes._resolve_nuclei_binary() == str(nuclei)


def test_nuclei_exit_error_explains_sigkill_oom():
    message = _nuclei_exit_error(-9)

    assert "SIGKILL" in message
    assert "out of memory" in message
    assert "NUCLEI_CONCURRENCY" in message


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



def test_parse_nuclei_stats_json_does_not_look_like_finding():
    line = '{"templates":120,"hosts":4,"requests":80,"matched":2,"errors":1,"rps":9.5,"percent":42}'

    assert _looks_like_nuclei_finding({"templates": 120, "hosts": 4}) is False
    stats = _parse_nuclei_stats_line(line)

    assert stats["templates"] == 120
    assert stats["hosts"] == 4
    assert stats["requests"] == 80
    assert stats["matched"] == 2
    assert stats["errors"] == 1
    assert stats["rps"] == 9.5
    assert stats["percent"] == 42


def test_parse_nuclei_text_stats_line():
    stats = _parse_nuclei_stats_line("Templates: 30 | Hosts: 3 | Requests: 99 | Matched: 1 | Errors: 0 | RPS: 7")

    assert stats["templates"] == 30
    assert stats["hosts"] == 3
    assert stats["requests"] == 99
    assert stats["matched"] == 1
    assert stats["errors"] == 0
    assert stats["rps"] == 7


def test_resolve_nuclei_binary_prefers_configured_executable(tmp_path, monkeypatch):
    nuclei = tmp_path / "nuclei"
    nuclei.write_text("#!/bin/sh\nexit 0\n")
    nuclei.chmod(0o755)

    monkeypatch.setenv("NUCLEI_BIN", str(nuclei))
    monkeypatch.setenv("PATH", "")

    assert _resolve_nuclei_binary() == str(nuclei)


def test_ensure_nuclei_templates_requires_yaml_templates(tmp_path, monkeypatch):
    import api.routes as routes

    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "README.md").write_text("not a nuclei template\n")
    captured = {}

    class FakeRun:
        returncode = 0
        stdout = "download complete"
        stderr = ""

    def fake_run(cmd, text, capture_output, timeout):
        captured["cmd"] = cmd
        return FakeRun()

    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(template_dir))
    monkeypatch.setattr(routes, "_nuclei_supports_flag", lambda nuclei_bin, flag: flag == "-ud")
    monkeypatch.setattr(routes.subprocess, "run", fake_run)

    ok, message = _ensure_nuclei_templates("/bin/nuclei")

    assert ok is False
    assert "Failed to download nuclei templates automatically" in message
    assert captured["cmd"] == ["/bin/nuclei", "-ut", "-ud", str(template_dir)]


def test_nuclei_list_public_includes_persisted_jobs(monkeypatch):
    import api.routes as routes

    routes._nuclei_state.clear()
    persisted_job = {
        "id": "scan-persisted",
        "type": "nuclei_scan",
        "project_id": "p1",
        "status": "done",
        "started_at": "2026-06-01T00:00:00Z",
        "payload": {
            "project_name": "Project",
            "scan_mode": "all_subdomains",
            "hosts_scanned": 2,
            "findings": [{"template_id": "tpl-1"}],
            "stats": {"hosts": 2, "matched": 1},
        },
    }

    monkeypatch.setattr(routes.jobs, "list_jobs", lambda **kwargs: [persisted_job])
    monkeypatch.setattr(routes.jobs, "get_job", lambda job_id: persisted_job if job_id == "scan-persisted" else None)

    rows = _nuclei_list_public(project_id="p1", limit=5)

    assert rows
    assert rows[0]["id"] == "scan-persisted"
    assert rows[0]["findings"][0]["template_id"] == "tpl-1"


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


def test_nuclei_command_safe_mode_caps_resources(monkeypatch):
    monkeypatch.setenv("NUCLEI_RATE_LIMIT", "100")
    monkeypatch.setenv("NUCLEI_CONCURRENCY", "50")
    monkeypatch.setenv("NUCLEI_BULK_SIZE", "50")
    monkeypatch.setenv("NUCLEI_TIMEOUT", "5")

    cmd = _nuclei_command("/bin/nuclei", "/tmp/targets", "/tmp/templates", safe_mode=True)

    assert cmd[cmd.index("-rl") + 1] == "5"
    assert cmd[cmd.index("-c") + 1] == "2"
    assert cmd[cmd.index("-bs") + 1] == "2"
    assert cmd[cmd.index("-timeout") + 1] == "10"


def test_nuclei_exit_error_explains_exit_code_9():
    message = _nuclei_exit_error(9)

    assert "exit code 9" in message
    assert "resource pressure" in message
    assert "automatically retries" in message
