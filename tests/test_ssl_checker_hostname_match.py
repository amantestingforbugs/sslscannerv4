from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from core.ssl_checker import is_hostname_match


def test_exact_certificate_name_matches_hostname():
    assert is_hostname_match("app.example.com", ["app.example.com"])
    assert is_hostname_match("APP.EXAMPLE.COM.", ["app.example.com"])


def test_wildcard_matches_only_one_leftmost_label():
    assert is_hostname_match("api.example.com", ["*.example.com"])
    assert not is_hostname_match("example.com", ["*.example.com"])
    assert not is_hostname_match("deep.api.example.com", ["*.example.com"])
    assert not is_hostname_match("badexample.com", ["*.example.com"])


def test_invalid_wildcards_do_not_hide_mismatches():
    assert not is_hostname_match("api.example.com", ["api.*.com"])
    assert not is_hostname_match("api.example.com", ["*api.example.com"])


def test_ip_certificate_names_match_only_exact_ip():
    assert is_hostname_match("192.0.2.10", ["192.0.2.10"])
    assert not is_hostname_match("192.0.2.10", ["*.0.2.10", "192.0.2.11"])


def test_run_checker_ignores_invalid_worker_env(monkeypatch):
    from core import ssl_checker

    monkeypatch.setenv("SSL_MAX_WORKERS", "not-a-number")
    monkeypatch.setattr(ssl_checker, "get_cert_info", lambda host: {"hostname": host, "error": None})

    assert ssl_checker.run_checker(["example.com"], max_workers=2) == [{"hostname": "example.com", "error": None}]


def test_run_checker_converts_unexpected_worker_exception_to_result(monkeypatch):
    from core import ssl_checker

    def boom(host):
        raise RuntimeError("unexpected worker failure")

    monkeypatch.setattr(ssl_checker, "get_cert_info", boom)

    [result] = ssl_checker.run_checker(["example.com"], max_workers=1)
    assert result["error"] == "unexpected worker failure"
    assert result["is_ignored_error"] is False
