from pathlib import Path
import re


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
