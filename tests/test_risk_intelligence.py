from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from api.routes import _compute_risk_intelligence


def test_risk_score_and_grade_are_weighted():
    latest = {"mismatches": 10, "expired": 2, "expiring": 5, "errors": 3}
    model = _compute_risk_intelligence(100, latest)
    assert model["score"] == 11.0
    assert model["grade"] == "low"
    assert model["exposure"]["expired_pct"] == 2.0


def test_risk_trend_detects_improvement():
    previous = {"mismatches": 20, "expired": 4, "expiring": 10, "errors": 5}
    latest = {"mismatches": 4, "expired": 1, "expiring": 3, "errors": 1}
    model = _compute_risk_intelligence(100, latest, previous)
    assert model["trend"] == "down"
    assert model["previous_score"] > model["score"]
    assert model["recommended_actions"][0]["title"] == "Rotate expired certificates"
