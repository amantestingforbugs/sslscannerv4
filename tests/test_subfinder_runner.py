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
    _query_certspotter_for_root,
    _query_hackertarget_for_root,
    _query_wayback_for_root,
    _query_alienvault_otx_for_root,
    _query_threatcrowd_for_root,
    _query_urlscan_for_root,
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


def test_query_certspotter_for_root_parses_dns_names(monkeypatch):
    monkeypatch.setattr(
        runner,
        "_http_json_with_retries",
        lambda *args, **kwargs: [
            {"dns_names": ["api.example.com", "*.dev.example.com", "bad.net"]},
            {"dns_names": ["shop.example.com"]},
        ],
    )
    found = _query_certspotter_for_root("example.com")
    assert found == ["api.example.com", "dev.example.com", "shop.example.com"]


def test_query_hackertarget_for_root_parses_csv_rows(monkeypatch):
    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b"api.example.com,1.1.1.1\n*.dev.example.com,2.2.2.2\nbad.net,8.8.8.8"

    monkeypatch.setattr(runner, "urlopen", lambda *args, **kwargs: _FakeResponse())
    found = _query_hackertarget_for_root("example.com")
    assert found == ["api.example.com", "dev.example.com"]


def test_query_wayback_for_root_extracts_hosts(monkeypatch):
    monkeypatch.setattr(
        runner,
        "_http_json_with_retries",
        lambda *args, **kwargs: [
            ["original"],
            ["https://portal.example.com/login"],
            ["http://cdn.example.com/static/app.js"],
            ["https://bad.net/"],
        ],
    )
    found = _query_wayback_for_root("example.com")
    assert found == ["cdn.example.com", "portal.example.com"]


def test_query_alienvault_otx_for_root_parses_passive_dns(monkeypatch):
    monkeypatch.setattr(
        runner,
        "_http_json_with_retries",
        lambda *args, **kwargs: {
            "passive_dns": [
                {"hostname": "api.example.com"},
                {"hostname": "*.dev.example.com"},
                {"hostname": "bad.net"},
            ]
        },
    )
    found = _query_alienvault_otx_for_root("example.com")
    assert found == ["api.example.com", "dev.example.com"]


def test_query_threatcrowd_for_root_parses_subdomain_list(monkeypatch):
    monkeypatch.setattr(
        runner,
        "_http_json_with_retries",
        lambda *args, **kwargs: {"subdomains": ["portal.example.com", "*.cdn.example.com", "bad.net"]},
    )
    found = _query_threatcrowd_for_root("example.com")
    assert found == ["cdn.example.com", "portal.example.com"]


def test_query_urlscan_for_root_parses_task_and_page_domains(monkeypatch):
    monkeypatch.setattr(
        runner,
        "_http_json_with_retries",
        lambda *args, **kwargs: {
            "results": [
                {"task": {"domain": "api.example.com"}, "page": {"domain": "www.example.com"}},
                {"task": {"domain": "bad.net"}, "page": {"apexDomain": "example.com"}},
            ]
        },
    )
    found = _query_urlscan_for_root("example.com")
    assert found == ["api.example.com", "example.com", "www.example.com"]


def test_build_subfinder_cmd_adds_aggressive_supported_flags(monkeypatch):
    monkeypatch.setattr(runner, "_subfinder_supports_flag", lambda *_args, flag=None: True)
    cmd = runner._build_subfinder_cmd("subfinder", "example.com")
    assert "-all" in cmd
    assert "-recursive" in cmd


def test_build_subfinder_cmd_skips_unsupported_extra_flags(monkeypatch):
    monkeypatch.setenv("SUBFINDER_EXTRA_FLAGS", "-all -recursive -nW")

    def fake_support(_bin, flag):
        return flag in {"-all", "-recursive"}

    monkeypatch.setattr(runner, "_subfinder_supports_flag", fake_support)
    cmd = runner._build_subfinder_cmd("subfinder", "example.com")
    assert "-all" in cmd
    assert "-recursive" in cmd
    assert "-nW" not in cmd
