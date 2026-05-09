from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from subfinder import runner
from subfinder.runner import (
    _extract_project_root_domains,
    _normalize_host,
    _is_host_within_root,
    _generate_bruteforce_candidates,
    _bruteforce_dns_hosts,
    _query_crtsh_for_root,
    _query_bufferover_for_root,
    _query_rapiddns_for_root,
)


def test_normalize_host_handles_urls_wildcards_and_ports():
    assert _normalize_host("https://API.Example.com:8443/v1") == "api.example.com"
    assert _normalize_host("*.shop.example.org") == "shop.example.org"
    assert _normalize_host("foo.example.net:443") == "foo.example.net"


def test_extract_project_root_domains_from_mixed_input():
    hosts = [
        "https://a.example.com/path",
        "*.b.example.com",
        "c.example.net,d.example.net",
        "api.demo.co.uk;www.demo.co.uk",
        "invalid_host",
    ]
    roots = _extract_project_root_domains(hosts)
    assert roots == ["demo.co.uk", "example.com", "example.net"]


def test_is_host_within_root_requires_domain_boundary():
    assert _is_host_within_root("a.example.com", "example.com") is True
    assert _is_host_within_root("example.com", "example.com") is True
    assert _is_host_within_root("badexample.com", "example.com") is False


def test_generate_bruteforce_candidates_includes_nested_label_patterns():
    candidates = _generate_bruteforce_candidates(
        "example.com",
        ["api.example.com", "portal.example.com", "outside.net"],
    )
    assert "www.example.com" in candidates
    assert "admin.api.example.com" in candidates
    assert "dev.portal.example.com" in candidates
    assert all(c.endswith(".example.com") for c in candidates)


def test_bruteforce_dns_hosts_filters_to_resolvable_entries(monkeypatch):
    def fake_resolver(host: str, timeout: float = 1.5):
        return host in {"www.example.com", "admin.api.example.com"}

    monkeypatch.setattr(runner, "_host_resolves", fake_resolver)
    found = _bruteforce_dns_hosts("example.com", ["api.example.com"], max_candidates=500)
    assert found == ["admin.api.example.com", "www.example.com"]


def test_query_crtsh_for_root_parses_name_value_lines(monkeypatch):
    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b'[{"name_value":"api.example.com\\n*.dev.example.com\\nnot-example.org"}]'

    monkeypatch.setattr(runner, "urlopen", lambda *args, **kwargs: _FakeResponse())
    found = _query_crtsh_for_root("example.com")
    assert found == ["api.example.com", "dev.example.com"]


def test_query_bufferover_for_root_parses_fdns_records(monkeypatch):
    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b'{"FDNS_A":["1.1.1.1,api.example.com","2.2.2.2,*.dev.example.com"],"RDNS":[]}'

    monkeypatch.setattr(runner, "urlopen", lambda *args, **kwargs: _FakeResponse())
    found = _query_bufferover_for_root("example.com")
    assert found == ["api.example.com", "dev.example.com"]


def test_query_rapiddns_for_root_extracts_hostnames_from_html(monkeypatch):
    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b"<td>portal.example.com</td><a>cdn.example.com</a><span>badexample.com</span>"

    monkeypatch.setattr(runner, "urlopen", lambda *args, **kwargs: _FakeResponse())
    found = _query_rapiddns_for_root("example.com")
    assert found == ["cdn.example.com", "portal.example.com"]
