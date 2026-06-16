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

def test_resolve_subfinder_bin_uses_env_override(tmp_path, monkeypatch):
    custom_bin = tmp_path / "custom-subfinder"
    custom_bin.write_text("#!/bin/sh\n")
    monkeypatch.setattr(runner.shutil, "which", lambda _name: None)
    monkeypatch.setenv("SUBFINDER_BIN", str(custom_bin))

    assert runner._resolve_subfinder_bin() == str(custom_bin)


def test_resolve_subfinder_bin_checks_home_go_bin(tmp_path, monkeypatch):
    home = tmp_path / "home"
    go_bin = home / "go" / "bin"
    go_bin.mkdir(parents=True)
    subfinder_bin = go_bin / "subfinder"
    subfinder_bin.write_text("#!/bin/sh\n")

    monkeypatch.setattr(runner.shutil, "which", lambda _name: None)
    monkeypatch.delenv("SUBFINDER_BIN", raising=False)
    monkeypatch.setenv("HOME", str(home))
    original_is_file = Path.is_file

    def fake_is_file(path):
        if str(path) == "/usr/local/bin/subfinder" or str(path) == "/root/go/bin/subfinder":
            return False
        return original_is_file(path)

    monkeypatch.setattr(Path, "is_file", fake_is_file)

    assert runner._resolve_subfinder_bin() == str(subfinder_bin)


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


def test_scheduled_project_subfinder_scans_all_discovered_hosts(monkeypatch):
    monkeypatch.delenv("SUBFINDER_SCAN_ALL_DISCOVERED", raising=False)

    assert runner._subfinder_ssl_scan_targets(
        ["api.example.com", "www.example.com"],
        ["api.example.com"],
        triggered_by="manual",
    ) == ["api.example.com"]
    assert runner._subfinder_ssl_scan_targets(
        ["api.example.com", "www.example.com"],
        ["api.example.com"],
        triggered_by="scheduler",
    ) == ["api.example.com", "www.example.com"]

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


def test_query_urlscan_for_root_paginates_and_extracts_nested_lists(monkeypatch):
    calls = []

    def fake_json(url, *args, **kwargs):
        calls.append(url)
        if len(calls) == 1:
            return {
                "results": [{"page": {"url": "https://api.example.com/v1"}, "lists": {"domains": ["cdn.example.com"]}}],
                "search_after": [123, "abc"],
            }
        return {"results": [{"task": {"domain": "portal.example.com"}}]}

    monkeypatch.setenv("URLSCAN_MAX_PAGES", "2")
    monkeypatch.setattr(runner, "_http_json_with_retries", fake_json)
    found = _query_urlscan_for_root("example.com")
    assert found == ["api.example.com", "cdn.example.com", "portal.example.com"]
    assert "search_after=123%2Cabc" in calls[1]


def test_build_subfinder_cmd_adds_aggressive_supported_flags(monkeypatch):
    monkeypatch.setattr(runner, "_subfinder_supports_flag", lambda *_args, flag=None: True)
    cmd = runner._build_subfinder_cmd("subfinder", "example.com")
    assert "-all" in cmd
    assert "-recursive" in cmd
    assert "-active" in cmd
    assert cmd[cmd.index("-timeout") + 1] == "60"


def test_build_subfinder_cmd_allows_deeper_timeout_override(monkeypatch):
    monkeypatch.setenv("SUBFINDER_TOOL_TIMEOUT_SECONDS", "120")
    monkeypatch.setattr(runner, "_subfinder_supports_flag", lambda *_args, **_kwargs: False)
    cmd = runner._build_subfinder_cmd("subfinder", "example.com")
    assert cmd[cmd.index("-timeout") + 1] == "120"


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
    assert {"findomain", "anubis", "subdomain_center", "shodan", "chaos", "commoncrawl", "github_code", "censys", "binaryedge"}.issubset(sources)


def test_query_virustotal_for_root_paginates(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "secret")
    calls = []

    def fake_json(url, *args, **kwargs):
        calls.append(url)
        if len(calls) == 1:
            return {"data": [{"id": "api.example.com"}], "links": {"next": "https://next.example/vt"}}
        return {"data": [{"id": "cdn.example.com"}, {"id": "bad.net"}], "links": {}}

    monkeypatch.setenv("VT_SUBDOMAIN_MAX_PAGES", "2")
    monkeypatch.setattr(runner, "_http_json_with_retries", fake_json)
    found = runner._query_virustotal_for_root("example.com")
    assert found == ["api.example.com", "cdn.example.com"]
    assert calls[1] == "https://next.example/vt"


def test_query_binaryedge_for_root_extracts_nested_hostnames(monkeypatch):
    monkeypatch.setenv("BINARYEDGE_API_KEY", "secret")
    monkeypatch.setattr(
        runner,
        "_http_json_with_retries",
        lambda *args, **kwargs: {"events": [{"domain": "api.example.com"}, {"domain": "bad.net"}]},
    )
    found = runner._query_binaryedge_for_root("example.com")
    assert found == ["api.example.com"]


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


def test_deep_enumeration_includes_subfinder_recursion_by_default(monkeypatch):
    monkeypatch.delenv("SUBDOMAIN_DEEP_SOURCES", raising=False)
    monkeypatch.setattr(
        runner,
        "_run_subfinder_hosts_for_root",
        lambda zone: ["admin.dev.example.com"] if zone == "dev.example.com" else [],
    )

    result = runner._run_recursive_passive_enumeration(
        ["example.com"],
        ["dev.example.com"],
        {},
    )

    assert result["found"] == ["admin.dev.example.com"]
    assert result["source_counts"]["deep:subfinder:d1"] == 1


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


def test_shared_subdomain_enumeration_combines_tool_passive_and_dns(monkeypatch):
    monkeypatch.setattr(
        runner,
        "_passive_enumeration_sources",
        lambda: {"passive": lambda root: ["www.example.com", "bad.net"]},
    )
    monkeypatch.setattr(
        runner,
        "_run_subfinder_for_root",
        lambda root, timeout=180: {"root_domain": root, "status": "done", "found": ["api.example.com"], "found_count": 1, "stderr": ""},
    )
    monkeypatch.setattr(runner, "_bruteforce_dns_hosts", lambda root, seed, max_candidates=0: ["admin.example.com"])
    monkeypatch.setattr(runner, "_permutation_dns_hosts", lambda root, seed, max_candidates=0: ["dev.example.com"])

    result = runner._run_subdomain_enumeration(["example.com"])

    assert result["found"] == ["admin.example.com", "api.example.com", "dev.example.com", "www.example.com"]
    assert result["source_map"]["subfinder"] == ["api.example.com"]
    assert result["source_map"]["passive"] == ["www.example.com"]
    assert result["source_map"]["dns_bruteforce"] == ["admin.example.com"]
    assert result["source_map"]["dns_permutation"] == ["dev.example.com"]


def test_domain_enumeration_and_project_subfinder_share_same_pipeline(monkeypatch):
    import db.database as db

    shared = {
        "found": ["api.example.com", "www.example.com"],
        "source_map": {"subfinder": ["api.example.com"], "passive": ["www.example.com"]},
        "source_counts": {"subfinder": 1, "passive": 1},
        "raw_records": [
            {"source": "subfinder", "root_domain": "example.com", "status": "done", "found_count": 1, "found_sample": ["api.example.com"]},
            {"source": "passive", "root_domain": "example.com", "status": "done", "found_count": 1, "found_sample": ["www.example.com"]},
        ],
    }
    calls = []
    monkeypatch.setattr(runner, "_run_subdomain_enumeration", lambda roots, depth_mode="aggressive": calls.append((tuple(roots), depth_mode)) or shared)
    monkeypatch.setattr(runner, "subfinder_available", lambda: True)
    monkeypatch.setattr(runner, "_resolve_active_hosts_with_httpx", lambda hosts: [])
    monkeypatch.setattr(runner, "_ssl_scan_subfinder_hosts", lambda *args, **kwargs: None)
    monkeypatch.setattr(db, "domain_enum_scan_create", lambda *args, **kwargs: "scan1")
    enum_rows = []
    monkeypatch.setattr(db, "domain_enum_results_add_batch", lambda scan_id, domain, hosts, source="mixed": enum_rows.append((domain, tuple(hosts), source)))
    monkeypatch.setattr(db, "domain_enum_scan_finish", lambda *args, **kwargs: None)
    monkeypatch.setattr(db, "project_get", lambda project_id: {"id": project_id, "name": "Example"})
    monkeypatch.setattr(db, "project_hosts", lambda project_id: ["example.com"])
    monkeypatch.setattr(db, "subfinder_job_create", lambda *args, **kwargs: "job1")
    monkeypatch.setattr(db, "subfinder_raw_result_add", lambda *args, **kwargs: "raw1")
    monkeypatch.setattr(db, "subfinder_raw_result_finish", lambda *args, **kwargs: None)
    inserted = {}
    monkeypatch.setattr(db, "subfinder_hosts_add_batch", lambda project_id, hosts: inserted.setdefault("hosts", tuple(hosts)) or (len(hosts), hosts))
    monkeypatch.setattr(db, "subfinder_new_discoveries_add_batch", lambda *args, **kwargs: None)
    monkeypatch.setattr(db, "subfinder_httpx_results_upsert_batch", lambda *args, **kwargs: None)
    monkeypatch.setattr(db, "subfinder_job_finish", lambda *args, **kwargs: None)
    monkeypatch.setattr(db, "subfinder_job_error", lambda *args, **kwargs: None)

    enum_result = runner.run_domain_enumeration_scan("example.com")
    job_id = runner.run_subfinder_for_project("project1", triggered_by="manual")

    assert calls == [(("example.com",), "standard"), (("example.com",), "aggressive")]
    assert enum_result["total_found"] == 2
    assert sorted(enum_rows) == [
        ("example.com", ("api.example.com",), "subfinder"),
        ("example.com", ("api.example.com",), "subfinder"),
        ("example.com", ("www.example.com",), "passive"),
        ("example.com", ("www.example.com",), "passive"),
    ]
    assert inserted["hosts"] == ("api.example.com", "www.example.com")
    assert job_id == "job1"



def test_standard_domain_enumeration_skips_deep_dns_stages(monkeypatch):
    monkeypatch.setattr(
        runner,
        "_passive_enumeration_sources",
        lambda: {"passive": lambda root: ["www.example.com"]},
    )
    monkeypatch.setattr(
        runner,
        "_run_subfinder_for_root",
        lambda root, timeout=180: {"root_domain": root, "status": "done", "found": ["api.example.com"], "found_count": 1, "stderr": ""},
    )

    def fail_expensive_stage(*_args, **_kwargs):
        raise AssertionError("standard depth should not run expensive deep/DNS stages")

    monkeypatch.setattr(runner, "_run_recursive_passive_enumeration", fail_expensive_stage)
    monkeypatch.setattr(runner, "_bruteforce_dns_hosts", fail_expensive_stage)
    monkeypatch.setattr(runner, "_permutation_dns_hosts", fail_expensive_stage)

    result = runner._run_subdomain_enumeration(["example.com"], depth_mode="standard")

    assert result["found"] == ["api.example.com", "www.example.com"]
    assert result["source_map"] == {"passive": ["www.example.com"], "subfinder": ["api.example.com"]}


def test_standard_domain_enumeration_uses_fast_source_subset(monkeypatch):
    calls = []

    monkeypatch.setattr(
        runner,
        "_passive_enumeration_sources",
        lambda: {
            "crtsh": lambda root: calls.append("crtsh") or ["ct.example.com"],
            "slow_optional": lambda root: calls.append("slow_optional") or ["slow.example.com"],
        },
    )
    monkeypatch.setattr(
        runner,
        "_run_subfinder_for_root",
        lambda root, timeout=180: calls.append(("subfinder", timeout)) or {"root_domain": root, "status": "done", "found": [], "found_count": 0, "stderr": ""},
    )

    result = runner._run_subdomain_enumeration(["example.com"], depth_mode="standard")

    assert result["found"] == ["ct.example.com"]
    assert "crtsh" in calls
    assert "slow_optional" not in calls
    assert ("subfinder", 90) in calls


def test_standard_domain_enumeration_allows_source_override(monkeypatch):
    calls = []
    monkeypatch.setenv("DOMAIN_ENUM_STANDARD_SOURCES", "slow_optional")
    monkeypatch.setattr(
        runner,
        "_passive_enumeration_sources",
        lambda: {
            "crtsh": lambda root: calls.append("crtsh") or ["ct.example.com"],
            "slow_optional": lambda root: calls.append("slow_optional") or ["slow.example.com"],
        },
    )
    monkeypatch.setattr(
        runner,
        "_run_subfinder_for_root",
        lambda root, timeout=180: {"root_domain": root, "status": "done", "found": [], "found_count": 0, "stderr": ""},
    )

    result = runner._run_subdomain_enumeration(["example.com"], depth_mode="standard")

    assert result["found"] == ["slow.example.com"]
    assert calls == ["slow_optional"]

def test_shared_enumeration_runs_deep_passive_before_dns(monkeypatch):
    monkeypatch.setattr(
        runner,
        "_passive_enumeration_sources",
        lambda: {"passive": lambda root: ["dev.example.com"]},
    )
    monkeypatch.setattr(
        runner,
        "_run_subfinder_for_root",
        lambda root, timeout=180: {"root_domain": root, "status": "done", "found": [], "found_count": 0, "stderr": ""},
    )
    monkeypatch.setattr(
        runner,
        "_run_recursive_passive_enumeration",
        lambda roots, discovered, sources: {
            "found": ["api.internal.dev.example.com"],
            "source_counts": {"deep:passive:d1": 1},
            "raw_records": [{"source": "deep:passive:d1", "root_domain": "dev.example.com", "status": "done", "found_count": 1}],
        },
    )

    def fake_bruteforce(root, seed, max_candidates=0):
        assert "api.internal.dev.example.com" in seed
        return ["admin.api.internal.dev.example.com"]

    monkeypatch.setattr(runner, "_bruteforce_dns_hosts", fake_bruteforce)
    monkeypatch.setattr(runner, "_permutation_dns_hosts", lambda root, seed, max_candidates=0: [])

    result = runner._run_subdomain_enumeration(["example.com"])

    assert result["found"] == [
        "admin.api.internal.dev.example.com",
        "api.internal.dev.example.com",
        "dev.example.com",
    ]
    assert result["source_map"]["deep_recursive_passive"] == ["api.internal.dev.example.com"]
    assert result["source_map"]["dns_bruteforce"] == ["admin.api.internal.dev.example.com"]


def test_domain_enumeration_initializes_database_before_scan(tmp_path, monkeypatch):
    import db.database as db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "fresh-enum.sqlite3")
    if getattr(db._local, "c", None):
        db._local.c.close()
        db._local.c = None
    monkeypatch.setattr(
        runner,
        "_run_subdomain_enumeration",
        lambda roots, depth_mode="standard": {
            "found": ["api.example.com"],
            "source_map": {"passive": ["api.example.com"]},
            "source_counts": {"passive": 1},
            "raw_records": [],
        },
    )

    result = runner.run_domain_enumeration_scan("example.com")

    assert result["total_found"] == 1
    scan = db.domain_enum_scan_get(result["scan_id"])
    rows = db.domain_enum_results_by_scan(result["scan_id"])
    assert scan["status"] == "done"
    assert rows[0]["hostname"] == "api.example.com"


def test_domain_enumeration_marks_scan_failed_on_pipeline_error(tmp_path, monkeypatch):
    import db.database as db
    import pytest

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "failed-enum.sqlite3")
    if getattr(db._local, "c", None):
        db._local.c.close()
        db._local.c = None

    def raise_pipeline_error(*_args, **_kwargs):
        raise RuntimeError("source crash")

    monkeypatch.setattr(runner, "_run_subdomain_enumeration", raise_pipeline_error)

    with pytest.raises(RuntimeError, match="source crash"):
        runner.run_domain_enumeration_scan("example.com")

    scans = db.domain_enum_scans_list()
    assert len(scans) == 1
    assert scans[0]["status"] == "failed"
    assert scans[0]["total_found"] == 0


def test_subdomain_enumeration_respects_configured_result_cap(monkeypatch):
    monkeypatch.setenv("DOMAIN_ENUM_MAX_RESULTS", "2")
    monkeypatch.setattr(
        runner,
        "_passive_enumeration_sources",
        lambda: {"passive": lambda root: ["www.example.com", "app.example.com", "extra.example.com"]},
    )
    monkeypatch.setattr(
        runner,
        "_run_subfinder_for_root",
        lambda root, timeout=180: {
            "root_domain": root,
            "status": "done",
            "found": ["api.example.com", "dev.example.com"],
            "found_count": 2,
            "stderr": "",
        },
    )

    def fail_late_stage(*_args, **_kwargs):
        raise AssertionError("enumeration should stop once DOMAIN_ENUM_MAX_RESULTS is reached")

    monkeypatch.setattr(runner, "_run_recursive_passive_enumeration", fail_late_stage)
    monkeypatch.setattr(runner, "_bruteforce_dns_hosts", fail_late_stage)
    monkeypatch.setattr(runner, "_permutation_dns_hosts", fail_late_stage)

    result = runner._run_subdomain_enumeration(["example.com"], depth_mode="aggressive")

    assert len(result["found"]) == 2
    assert result["found"] == ["api.example.com", "dev.example.com"]


def test_domain_enumeration_verbose_log_persists_source_hosts_and_errors(tmp_path, monkeypatch):
    import db.database as db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "verbose-enum.sqlite3")
    if getattr(db._local, "c", None):
        db._local.c.close()
        db._local.c = None
    monkeypatch.setattr(
        runner,
        "_run_subdomain_enumeration",
        lambda roots, depth_mode="standard": {
            "found": ["api.example.com"],
            "source_map": {"subfinder": ["api.example.com"]},
            "source_counts": {"subfinder": 1},
            "raw_records": [
                {
                    "source": "subfinder",
                    "root_domain": "example.com",
                    "status": "error",
                    "found_count": 1,
                    "found_sample": ["api.example.com"],
                    "stderr_preview": "provider timeout",
                }
            ],
        },
    )

    result = runner.run_domain_enumeration_scan("example.com", verbose=True)
    scan = db.domain_enum_scan_get(result["scan_id"])

    assert result["verbose_log"][0]["hosts"] == ["api.example.com"]
    assert scan["verbose_log"][0]["error"] == "provider timeout"
    assert scan["verbose_log"][0]["hosts"] == ["api.example.com"]
