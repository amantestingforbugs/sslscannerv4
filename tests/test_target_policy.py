from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from flask import Flask

import api.routes as routes
from core.ssl_checker import get_cert_info
from core.target_policy import (
    filter_allowed_hosts,
    is_target_allowed,
    normalize_hostname,
    registered_domain,
    resolves_to_disallowed_ip,
)


def test_target_policy_blocks_private_literals_and_enforces_scope(monkeypatch):
    monkeypatch.setenv("SCAN_ALLOWED_DOMAINS", "example.com, bugcrowd.net")
    monkeypatch.delenv("ALLOW_PRIVATE_SCAN_TARGETS", raising=False)

    assert normalize_hostname("https://App.Example.com:8443/login") == "app.example.com"
    assert registered_domain("deep.app.example.co.uk") == "example.co.uk"
    assert is_target_allowed("api.example.com") is True
    assert is_target_allowed("out-of-scope.test") is False
    assert is_target_allowed("127.0.0.1") is False

    allowed, rejected = filter_allowed_hosts(["api.example.com", "10.0.0.5", "evil.test"])
    assert allowed == ["api.example.com"]
    assert rejected == ["10.0.0.5", "evil.test"]


def test_ssl_checker_short_circuits_hosts_that_resolve_private(monkeypatch):
    resolves_to_disallowed_ip.cache_clear()

    def fake_getaddrinfo(host, port, type=0):
        return [(None, None, None, None, ("10.1.2.3", port))]

    monkeypatch.setattr("core.target_policy.socket.getaddrinfo", fake_getaddrinfo)
    result = get_cert_info("internal.example.com")

    assert result["error"] == "Target outside authorized scope or resolves to a disallowed network"
    assert result["is_ignored_error"] is True


def test_api_key_auth_can_be_required(monkeypatch):
    monkeypatch.setenv("API_REQUIRE_KEY", "true")
    monkeypatch.setenv("API_KEY", "secret")

    app = Flask(__name__)
    app.register_blueprint(routes.api)
    client = app.test_client()

    denied = client.get("/api/security-policy")
    allowed = client.get("/api/security-policy", headers={"X-API-Key": "secret"})

    assert denied.status_code == 401
    assert allowed.status_code == 200
    assert allowed.get_json()["data"]["api_key_required"] is True



def test_webhook_url_validation_rejects_hosts_resolving_private(monkeypatch):
    routes.resolves_to_disallowed_ip.cache_clear()

    def fake_getaddrinfo(host, port, type=0):
        return [(None, None, None, None, ("10.0.0.12", port))]

    monkeypatch.delenv("ALLOW_PRIVATE_SCAN_TARGETS", raising=False)
    monkeypatch.setattr("core.target_policy.socket.getaddrinfo", fake_getaddrinfo)

    try:
        routes._validate_webhook_url("https://hooks.example.com/notify")
        assert False, "Expected private DNS webhook target to be rejected"
    except ValueError as exc:
        assert "not allowed" in str(exc)
