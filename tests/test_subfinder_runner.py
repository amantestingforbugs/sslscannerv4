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
        if host.startswith("ssl-sentinel-nohit"):
            return set()
        return {"203.0.113.10"} if host in {"www.example.com", "admin.api.example.com"} else set()

    monkeypatch.setattr(runner, "_resolve_host_ips", fake_resolver)
    found = _bruteforce_dns_hosts("example.com", ["api.example.com"], max_candidates=1500)
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


def test_query_anubis_for_root_parses_public_json(monkeypatch):
    monkeypatch.setattr(
        runner,
        "_http_json_with_retries",
        lambda *args, **kwargs: ["api.example.com", "*.dev.example.com", "bad.net"],
    )
    found = runner._query_anubis_for_root("example.com")
    assert found == ["api.example.com", "dev.example.com"]


def test_query_subdomain_center_for_root_parses_public_json(monkeypatch):
    monkeypatch.setattr(
        runner,
        "_http_json_with_retries",
        lambda *args, **kwargs: ["portal.example.com", "cdn.example.com", "bad.net"],
    )
    found = runner._query_subdomain_center_for_root("example.com")
    assert found == ["cdn.example.com", "portal.example.com"]


def test_query_shodan_for_root_parses_keyed_api(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "secret")
    monkeypatch.setattr(
        runner,
        "_http_json_with_retries",
        lambda *args, **kwargs: {
            "subdomains": ["api", "www"],
            "data": [{"subdomain": "dev"}, {"subdomain": "bad.net"}],
        },
    )
    found = runner._query_shodan_for_root("example.com")
    assert found == ["api.example.com", "dev.example.com", "www.example.com"]


def test_build_subfinder_cmd_preserves_supported_extra_flag_values(monkeypatch):
    monkeypatch.setenv("SUBFINDER_EXTRA_FLAGS", "-rate-limit 50 -nW")

    def fake_support(_bin, flag):
        return flag in {"-all", "-recursive", "-rate-limit"}

    monkeypatch.setattr(runner, "_subfinder_supports_flag", fake_support)
    cmd = runner._build_subfinder_cmd("subfinder", "example.com")
    assert "-rate-limit" in cmd
    assert cmd[cmd.index("-rate-limit") + 1] == "50"
    assert "-nW" not in cmd


def test_passive_enumeration_sources_include_all_optional_integrations():
    sources = runner._passive_enumeration_sources()
    assert {"findomain", "anubis", "subdomain_center", "shodan", "chaos", "commoncrawl", "github_code"}.issubset(sources)


def test_brute_labels_uses_builtin_top_n_without_network(monkeypatch):
    monkeypatch.delenv("DNS_BRUTEFORCE_LABELS", raising=False)
    monkeypatch.delenv("DNS_BRUTEFORCE_WORDLIST_FILES", raising=False)
    monkeypatch.delenv("DNS_BRUTEFORCE_WORDLIST_URLS", raising=False)
    monkeypatch.setenv("DNS_BRUTEFORCE_TOP_N", "1000")
    labels = runner._brute_labels()
    assert "www" in labels
    assert "api" in labels
    assert "api30" in labels
    assert len(labels) == 1000


def test_bruteforce_dns_hosts_filters_wildcard_dns(monkeypatch):
    def fake_resolve(host: str, timeout: float = 1.5):
        if host.startswith("ssl-sentinel-nohit"):
            return {"203.0.113.10"}
        if host == "www.example.com":
            return {"203.0.113.20"}
        if host == "api.example.com":
            return {"203.0.113.10"}
        return set()

    monkeypatch.setenv("DNS_BRUTEFORCE_LABELS", "www,api")
    monkeypatch.setattr(runner, "_resolve_host_ips", fake_resolve)
    found = _bruteforce_dns_hosts("example.com", [], max_candidates=10)
    assert found == ["www.example.com"]


def test_query_commoncrawl_for_root_parses_json_lines(monkeypatch):
    def fake_json(url, *args, **kwargs):
        assert url == "https://index.commoncrawl.org/collinfo.json"
        return [{"id": "CC-MAIN-2026-01"}]

    def fake_text(url, *args, **kwargs):
        assert "CC-MAIN-2026-01-index" in url
        return '{"url":"https://api.example.com/v1"}\nnot json https://cdn.example.com/app.js\nhttps://bad.net/'

    monkeypatch.setattr(runner, "_http_json_with_retries", fake_json)
    monkeypatch.setattr(runner, "_http_text_with_retries", fake_text)
    found = runner._query_commoncrawl_for_root("example.com")
    assert found == ["api.example.com", "cdn.example.com"]


def test_query_github_code_for_root_requires_token_and_parses_text_matches(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    monkeypatch.setattr(
        runner,
        "_http_json_with_retries",
        lambda *args, **kwargs: {
            "items": [
                {
                    "name": "config",
                    "path": "deploy/api.example.com.yml",
                    "text_matches": [{"fragment": "BASE_URL=https://portal.example.com bad.net"}],
                }
            ]
        },
    )
    found = runner._query_github_code_for_root("example.com")
    assert found == ["api.example.com", "portal.example.com"]


def test_iter_completed_with_deadline_yields_timeout_for_pending_future():
    from concurrent.futures import Future

    pending = Future()
    results = list(runner._iter_completed_with_deadline({pending: "slow-source"}, 1, "test phase"))

    assert len(results) == 1
    assert results[0][1] == "slow-source"
    assert results[0][2] is True
    assert pending.cancelled()


def test_subfinder_ssl_scan_targets_default_to_new_hosts(monkeypatch):
    monkeypatch.delenv("SUBFINDER_SCAN_ALL_DISCOVERED", raising=False)

    targets = runner._subfinder_ssl_scan_targets(
        ["api.example.com", "old.example.com"],
        ["api.example.com"],
    )

    assert targets == ["api.example.com"]


def test_subfinder_ssl_scan_targets_can_scan_all_discovered(monkeypatch):
    monkeypatch.setenv("SUBFINDER_SCAN_ALL_DISCOVERED", "1")

    targets = runner._subfinder_ssl_scan_targets(
        ["old.example.com", "api.example.com", "api.example.com"],
        ["api.example.com"],
    )

    assert targets == ["api.example.com", "old.example.com"]


def test_host_suffixes_under_root_yields_deepest_to_shallowest():
    assert runner._host_suffixes_under_root("api.internal.dev.example.com", "example.com") == [
        "api.internal.dev.example.com",
        "internal.dev.example.com",
        "dev.example.com",
    ]


def test_generate_bruteforce_candidates_prepends_to_every_known_subzone(monkeypatch):
    monkeypatch.setenv("DNS_BRUTEFORCE_LABELS", "www,admin")
    candidates = _generate_bruteforce_candidates(
        "example.com",
        ["api.internal.dev.example.com"],
    )
    assert "admin.api.internal.dev.example.com" in candidates
    assert "admin.internal.dev.example.com" in candidates
    assert "admin.dev.example.com" in candidates


def test_deep_scan_targets_prioritizes_deepest_unseen_zones():
    targets = runner._deep_scan_targets(
        "example.com",
        ["www.example.com", "api.internal.dev.example.com", "bad.net"],
        {"api.internal.dev.example.com"},
        limit=2,
    )
    assert targets == ["internal.dev.example.com", "dev.example.com"]


def test_recursive_passive_enumeration_walks_newly_found_subzones(monkeypatch):
    monkeypatch.setenv("SUBDOMAIN_DEEP_SCAN_DEPTH", "2")
    monkeypatch.setenv("SUBDOMAIN_DEEP_TARGETS_PER_ROOT", "10")
    monkeypatch.setenv("SUBDOMAIN_DEEP_SOURCES", "fake")

    def fake_source(zone: str):
        if zone == "dev.example.com":
            return ["api.dev.example.com"]
        if zone == "api.dev.example.com":
            return ["admin.api.dev.example.com"]
        return []

    result = runner._run_recursive_passive_enumeration(
        ["example.com"],
        ["dev.example.com"],
        {"fake": fake_source},
    )

    assert result["found"] == ["admin.api.dev.example.com", "api.dev.example.com"]
    assert result["source_counts"]["deep:fake:d1"] == 1
    assert result["source_counts"]["deep:fake:d2"] == 1


def test_bruteforce_dns_hosts_returns_partial_results_when_resolver_wedges(monkeypatch):
    import time

    monkeypatch.setenv("DNS_BRUTEFORCE_LABELS", "www,slow")
    monkeypatch.setenv("DNS_BRUTEFORCE_KEEP_WILDCARD", "1")
    monkeypatch.setenv("DNS_BRUTEFORCE_RESOLVE_TIMEOUT_SECONDS", "1")

    def fake_resolve(host: str, timeout: float = 1.5):
        if host == "www.example.com":
            return {"203.0.113.20"}
        time.sleep(2)
        return {"203.0.113.30"}

    monkeypatch.setattr(runner, "_resolve_host_ips", fake_resolve)
    started = time.monotonic()
    found = _bruteforce_dns_hosts("example.com", [], max_candidates=2)
    elapsed = time.monotonic() - started

    assert found == ["www.example.com"]
    assert elapsed < 1.8


def test_permutation_dns_hosts_returns_partial_results_when_resolver_wedges(monkeypatch):
    import time

    monkeypatch.setenv("DNS_BRUTEFORCE_LABELS", "api")
    monkeypatch.setenv("DNS_PERMUTATION_RESOLVE_TIMEOUT_SECONDS", "1")
    monkeypatch.setattr(
        runner,
        "_generate_permutation_candidates",
        lambda *_args, **_kwargs: {"api-old.example.com", "api-new.example.com"},
    )

    def fake_resolve(host: str, timeout: float = 1.5):
        if host == "api-new.example.com":
            return {"203.0.113.20"}
        time.sleep(2)
        return {"203.0.113.30"}

    monkeypatch.setattr(runner, "_resolve_host_ips", fake_resolve)
    started = time.monotonic()
    found = runner._permutation_dns_hosts("example.com", ["api.example.com"], max_candidates=2)
    elapsed = time.monotonic() - started

    assert found == ["api-new.example.com"]
    assert elapsed < 1.8
