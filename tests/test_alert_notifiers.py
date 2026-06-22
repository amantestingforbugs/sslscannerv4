from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from alerts.notifiers import AlertManager


def test_dispatchable_alert_ids_only_returns_alerts_enabled_by_rules():
    settings = {
        "rule_mismatch": 1,
        "rule_expired": 0,
        "rule_expiring": 1,
        "rule_error": 0,
        "mismatch_scope_filter": "all",
    }
    alerts = [
        {"id": "mismatch", "issue_type": "SSL Mismatch", "mismatch_scope": "different_domain"},
        {"id": "expired", "issue_type": "Expired"},
        {"id": "expiring", "issue_type": "Expiring Soon"},
        {"id": "error", "issue_type": "Scan Error"},
    ]

    assert AlertManager(settings).dispatchable_alert_ids(alerts) == ["mismatch", "expiring"]


def test_dispatchable_alert_ids_honors_mismatch_scope_filter():
    settings = {
        "rule_mismatch": 1,
        "rule_expired": 1,
        "rule_expiring": 1,
        "rule_error": 1,
        "mismatch_scope_filter": "same_domain",
    }
    alerts = [
        {"id": "same", "issue_type": "SSL Mismatch", "mismatch_scope": "same_domain"},
        {"id": "different", "issue_type": "SSL Mismatch", "mismatch_scope": "different_domain"},
        {"id": "expired", "issue_type": "Expired"},
    ]

    assert AlertManager(settings).dispatchable_alert_ids(alerts) == ["same", "expired"]


def test_telegram_notifier_escapes_html(monkeypatch):
    from alerts.notifiers import TelegramNotifier
    import urllib.parse

    captured = {}

    class DummyResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(req, timeout=10):
        captured["body"] = req.data.decode()
        return DummyResponse()

    monkeypatch.setattr("alerts.notifiers._urlopen_no_redirect", fake_urlopen)
    notifier = TelegramNotifier({
        "telegram_enabled": 1,
        "telegram_bot_token": "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcd",
        "telegram_chat_id": "chat",
    })

    assert notifier.send_mismatch_digest(
        "<Project&>",
        [{"hostname": "<host&>", "issue_type": "SSL Mismatch", "details": "CN <bad&>"}],
    ) is True

    payload = urllib.parse.parse_qs(captured["body"])
    text = payload["text"][0]
    assert "&lt;Project&amp;&gt;" in text
    assert "&lt;host&amp;&gt;" in text
    assert "CN &lt;bad&amp;&gt;" in text
    assert "<Project&>" not in text


def test_webhook_notifier_rejects_private_network_url(monkeypatch):
    from alerts.notifiers import WebhookNotifier

    called = {"sent": False}

    def fake_urlopen(req, timeout=10):
        called["sent"] = True
        raise AssertionError("private webhook URL should not be requested")

    monkeypatch.setattr("alerts.notifiers._urlopen_no_redirect", fake_urlopen)
    notifier = WebhookNotifier("slack", True, "https://127.0.0.1/hook")

    assert notifier.ready is False
    assert notifier.send_mismatch_digest("Project", [{"hostname": "a", "issue_type": "Expired", "details": "x"}]) is False
    assert called["sent"] is False


def test_webhook_notifier_rejects_redirects(monkeypatch):
    from alerts.notifiers import WebhookNotifier
    import urllib.error

    class RedirectResponse:
        status = 302

    def fake_urlopen(req, timeout=10):
        raise urllib.error.HTTPError(req.full_url, 302, "Found", {"Location": "https://example.com"}, None)

    monkeypatch.setattr("alerts.notifiers._is_safe_https_url", lambda url: True)
    monkeypatch.setattr("alerts.notifiers._urlopen_no_redirect", fake_urlopen)
    notifier = WebhookNotifier("slack", True, "https://hooks.slack.com/services/test")

    assert notifier.send_mismatch_digest("Project", [{"hostname": "a", "issue_type": "Expired", "details": "x"}]) is False


def test_telegram_notifier_rejects_malformed_token():
    from alerts.notifiers import TelegramNotifier

    notifier = TelegramNotifier({
        "telegram_enabled": 1,
        "telegram_bot_token": "../../bad-token",
        "telegram_chat_id": "chat",
    })

    assert notifier.ready is False
