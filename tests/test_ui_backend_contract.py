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


def test_frontend_assets_are_versioned_static_modules():
    assert "url_for('static', filename='css/base.css')" in TEMPLATE
    assert "url_for('static', filename='css/layout.css')" in TEMPLATE
    assert "url_for('static', filename='css/components.css')" in TEMPLATE
    assert 'type="module"' in TEMPLATE
    assert "url_for('static', filename='js/app.js')" in TEMPLATE
    assert "url_for('static', filename='js/api-types.js')" in TEMPLATE
    assert "<style>" not in TEMPLATE


def test_frontend_api_contracts_match_backend_envelope_helpers():
    routes = (ROOT / "api" / "routes.py").read_text()
    api_types = (ROOT / "static" / "js" / "api-types.js").read_text()
    assert '{"ok": True}' in routes
    assert '{"ok": False, "error": msg}' in routes
    assert "@typedef {Object} ApiEnvelope" in api_types
    assert "@property {boolean} ok" in api_types
    assert "@property {unknown=} data" in api_types
    assert "@property {string=} error" in api_types
    for contract in ("project", "scan", "alert", "nucleiFinding", "subfinderResult"):
        assert f"{contract}(value)" in api_types


def test_frontend_state_and_incremental_rendering_layers_exist():
    state = (ROOT / "static" / "js" / "ui-state.js").read_text()
    virtual_table = (ROOT / "static" / "js" / "virtual-table.js").read_text()
    for key in ("projects", "scans", "alerts", "nuclei", "subfinder"):
        assert key in state
    assert "subscribe(path, fn)" in state
    assert "renderRowsIncrementally" in virtual_table
    assert "virtualizeTableBody" in virtual_table
