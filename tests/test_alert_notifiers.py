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
