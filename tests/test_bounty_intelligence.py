from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from api.routes import _score_bounty_opportunity, _bounty_summary  # noqa: E402


def test_bounty_opportunity_prioritizes_live_cross_domain_mismatch():
    candidate = _score_bounty_opportunity(
        {
            "hostname": "admin.example.com",
            "cn": "other-tenant.vendor.net",
            "issuer": "Example CA",
            "expiry": "2026-12-31T00:00:00Z",
            "is_mismatch": 1,
            "same_base": 0,
            "http_is_active": 1,
            "status_code": 403,
            "page_title": "Admin Console",
            "final_url": "https://admin.example.com/login",
            "first_seen": "2026-06-01T00:00:00Z",
        },
        "Example Program",
    )

    assert candidate["severity"] in {"high", "critical"}
    assert candidate["score"] >= 75
    assert "cross-domain certificate mismatch" in candidate["signals"]
    assert "sensitive hostname keyword" in candidate["signals"]
    assert "Potential finding" in candidate["report_markdown"]
    assert "admin.example.com" in candidate["report_markdown"]


def test_bounty_summary_counts_high_value_buckets():
    candidates = [
        {"severity": "critical", "http": {"active": True}, "ssl": {"is_mismatch": True, "is_expired": False}},
        {"severity": "high", "http": {"active": False}, "ssl": {"is_mismatch": False, "is_expired": True}},
        {"severity": "medium", "http": {"active": True}, "ssl": {"is_mismatch": False, "is_expired": False}},
    ]

    summary = _bounty_summary(candidates)

    assert summary["total_candidates"] == 3
    assert summary["critical"] == 1
    assert summary["high"] == 1
    assert summary["live"] == 2
    assert summary["mismatches"] == 1
    assert summary["expired"] == 1
