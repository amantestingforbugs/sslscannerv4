from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app import app
import api.routes as routes


class _FakeDB:
    def __init__(self):
        self.previous = {
            "discord_enabled": 0,
            "discord_webhook_url": "",
        }
        self.updated = {
            "telegram_enabled": 0,
            "telegram_bot_token": "",
            "telegram_chat_id": "",
            "slack_enabled": 0,
            "slack_webhook_url": "",
            "discord_enabled": 1,
            "discord_webhook_url": "https://discord.example.com/webhook",
            "rule_mismatch": 1,
            "rule_expired": 1,
            "rule_expiring": 1,
            "rule_error": 0,
            "mismatch_scope_filter": "all",
            "minimum_days_left": 30,
        }
        self.requeue_count = 0

    def alert_settings_get(self):
        return dict(self.previous)

    def alert_settings_update(self, **_kwargs):
        return dict(self.updated)

    def alerts_mark_all_unsent(self):
        self.requeue_count += 1


class _FailingWebhookNotifier:
    def __init__(self, *_args, **_kwargs):
        pass

    def send_mismatch_digest(self, *_args, **_kwargs):
        return False


def test_discord_alerts_requeued_when_channel_check_fails(monkeypatch):
    fake_db = _FakeDB()
    monkeypatch.setattr(routes, "db", fake_db)
    monkeypatch.setattr(routes, "WebhookNotifier", _FailingWebhookNotifier)

    with app.test_client() as client:
        response = client.put(
            "/api/alert-settings",
            json={
                "discord_enabled": True,
                "discord_webhook_url": "https://discord.example.com/webhook",
                "rule_mismatch": True,
                "rule_expired": True,
                "rule_expiring": True,
                "rule_error": False,
                "minimum_days_left": 30,
            },
        )

    assert response.status_code == 400
    assert response.get_json()["error"] == "Saved, but webhook test failed for: discord"
    assert fake_db.requeue_count == 1
