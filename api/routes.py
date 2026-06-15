"""
api/routes.py — All REST endpoints + SSE stream for real-time UI updates.
Fixes:
  - Alert clear now pushes SSE event so counter resets without page refresh
  - All heavy ops are async — create_project is instant
  - Added /api/sse for real-time push to browser
  - Subfinder CRUD endpoints
"""

import json
import csv
import io
import queue
import threading
import time
import logging
import os
import subprocess
import shutil
import tempfile
import signal
import functools
import hmac
import re
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify, Response, stream_with_context

import db.database as db
from core import jobs
from core.ssl_checker import parse_hosts_file
from core.target_policy import (
    allow_private_targets,
    allowed_scope_domains,
    is_ip_disallowed,
    is_target_allowed,
    normalize_hostname as normalize_target_hostname,
    registered_domain,
)
from core.observability import subscribe, get_logs
from scheduler.runner import (
    run_project_scan_async,
    get_scan_state,
    list_active_scans,
    pause_scan,
    resume_scan,
    stop_scan,
)
from alerts.notifiers import WebhookNotifier, TelegramNotifier

log = logging.getLogger(__name__)
api = Blueprint("api", __name__, url_prefix="/api")

# ── SSE broadcast bus ─────────────────────────────────────────────────────────
# Each connected browser gets its own queue. Events pushed here reach all clients.
_sse_clients: list[queue.Queue] = []
_sse_lock = threading.Lock()
_openssl_threads: dict[str, threading.Thread] = {}
_openssl_status: dict[str, dict] = {}
_openssl_lock = threading.Lock()
_quick_scan_threads: dict[str, threading.Thread] = {}
_quick_scan_state: dict[str, dict] = {}
_quick_scan_lock = threading.Lock()
_nuclei_threads: dict[str, threading.Thread] = {}
_nuclei_state: dict[str, dict] = {}
_nuclei_lock = threading.Lock()
NUCLEI_LOG_BUFFER = 600
QUICK_SCAN_ROWS_BUFFER = 500
STARTED_AT_TS = time.time()



def _safe_int(value, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if min_value is not None:
        parsed = max(min_value, parsed)
    if max_value is not None:
        parsed = min(max_value, parsed)
    return parsed


def _is_private_or_local_host(host: str) -> bool:
    h = (host or "").strip().lower()
    if h in {"localhost", "127.0.0.1", "::1"}:
        return True
    return (not allow_private_targets()) and is_ip_disallowed(h)


def _resolve_nuclei_binary() -> str | None:
    configured = os.environ.get("NUCLEI_BIN", "").strip()
    if configured:
        configured_path = os.path.expanduser(configured)
        if os.path.isfile(configured_path) and os.access(configured_path, os.X_OK):
            return configured_path
        configured_on_path = shutil.which(configured)
        if configured_on_path:
            return configured_on_path

    bin_path = shutil.which("nuclei")
    if bin_path:
        return bin_path

    for candidate in ("/root/go/bin/nuclei", "/usr/local/bin/nuclei", "/usr/bin/nuclei"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _nuclei_templates_dir() -> str:
    configured = os.environ.get("NUCLEI_TEMPLATES_DIR", "").strip()
    return os.path.expanduser(configured) if configured else os.path.expanduser("~/nuclei-templates")


def _directory_has_files(path: str) -> bool:
    if not os.path.isdir(path):
        return False
    return any(os.path.isfile(os.path.join(root, name)) for root, _, files in os.walk(path) for name in files)


def _nuclei_template_count(path: str) -> int:
    if not os.path.isdir(path):
        return 0
    return sum(
        1
        for root, _, files in os.walk(path)
        for name in files
        if name.endswith((".yaml", ".yml"))
    )


@functools.lru_cache(maxsize=8)
def _nuclei_supported_flags(nuclei_bin: str) -> set[str]:
    """Return flags supported by the installed nuclei binary.

    ProjectDiscovery has renamed/added flags across releases, and users often run
    this app with a locally installed macOS/Windows/Linux nuclei binary. Building
    the command from the actual help output prevents scans from failing before
    they start just because an optional quality-of-life flag is unavailable.
    """
    try:
        run = subprocess.run(
            [nuclei_bin, "-h"],
            text=True,
            capture_output=True,
            timeout=15,
        )
    except Exception:
        return set()
    help_text = f"{run.stdout or ''}\n{run.stderr or ''}"
    return set(re.findall(r"(?<!\w)-{1,2}[A-Za-z][A-Za-z0-9-]*", help_text))


def _nuclei_supports_flag(nuclei_bin: str, flag: str) -> bool:
    flags = _nuclei_supported_flags(nuclei_bin)
    return not flags or flag in flags

def _nuclei_resource_settings() -> dict:
    return {
        "rate_limit": _safe_int(os.environ.get("NUCLEI_RATE_LIMIT"), 25, min_value=1, max_value=500),
        "concurrency": _safe_int(os.environ.get("NUCLEI_CONCURRENCY"), 10, min_value=1, max_value=100),
        "bulk_size": _safe_int(os.environ.get("NUCLEI_BULK_SIZE"), 10, min_value=1, max_value=100),
        "timeout": _safe_int(os.environ.get("NUCLEI_TIMEOUT"), 5, min_value=1, max_value=60),
    }


def _nuclei_exit_error(exit_code: int, stderr_tail: str = "", stdout_tail: str = "") -> str:
    detail = (stderr_tail or stdout_tail or "").strip()
    if exit_code == -9:
        hint = (
            "nuclei was killed by SIGKILL (exit code -9), usually because the container ran out of memory. "
            "The scan now uses conservative defaults; lower NUCLEI_RATE_LIMIT, NUCLEI_CONCURRENCY, or NUCLEI_BULK_SIZE further if this continues."
        )
        return f"{hint} Last output: {detail}" if detail else hint
    return detail or f"nuclei exited with code {exit_code}"


def _ensure_nuclei_templates(nuclei_bin: str) -> tuple[bool, str]:
    """
    Ensure nuclei templates exist locally.
    Returns (ok, message). Non-empty message is informational/warning text.
    """
    templates_dir = _nuclei_templates_dir()
    if _directory_has_files(templates_dir):
        return True, "templates already present"

    try:
        os.makedirs(templates_dir, exist_ok=True)
        update_cmd = [nuclei_bin, "-ut"]
        if _nuclei_supports_flag(nuclei_bin, "-ud"):
            update_cmd.extend(["-ud", templates_dir])
        init_run = subprocess.run(
            update_cmd,
            text=True,
            capture_output=True,
            timeout=300,
        )
        if init_run.returncode == 0 and _directory_has_files(templates_dir):
            return True, "Nuclei templates were missing and have been downloaded."
        detail = (init_run.stderr or init_run.stdout or "").strip()
        if not detail:
            detail = f"nuclei exited with code {init_run.returncode}"
        return False, f"Failed to download nuclei templates automatically. {detail}"
    except Exception as ex:
        return False, f"Failed to download nuclei templates automatically: {ex}"


def _normalize_nuclei_target(raw: str) -> str:
    host = normalize_target_hostname(raw, allow_ip=True)
    if not host or not is_target_allowed(host):
        return ""
    return host


def _normalize_nuclei_finding(row: dict) -> dict:
    info = row.get("info") or {}
    severity = (info.get("severity") or row.get("severity") or "unknown").lower()
    template_id = row.get("template_id") or row.get("template-id") or row.get("templateID") or ""
    matched_at = row.get("matched_at") or row.get("matched-at") or row.get("matched") or row.get("url") or ""
    host = row.get("host") or row.get("ip") or ""
    if isinstance(host, list):
        host = ", ".join(str(h) for h in host)
    return {
        **row,
        "host": host or matched_at,
        "matched_at": matched_at,
        "template_id": template_id,
        "info": {**info, "severity": severity, "name": info.get("name") or row.get("name") or template_id or "—"},
    }

def _validate_webhook_url(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("Webhook URLs must be valid https URLs")
    host = (parsed.hostname or "").strip().lower()
    if not host or _is_private_or_local_host(host):
        raise ValueError("Webhook URL host is not allowed")
    return value


def broadcast(event: str, data: dict):
    """Persist and push an event to all connected SSE clients."""
    if isinstance(data, dict):
        event_job_id = data.get("id") or data.get("scan_id") or data.get("job_id")
        if event_job_id:
            try:
                jobs.append_event(str(event_job_id), event, data)
            except Exception:
                log.debug("Unable to persist SSE event %s for job %s", event, event_job_id, exc_info=True)
    msg = f"event: {event}\ndata: {json.dumps(data)}\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)


def _handle_observability_event(evt: dict):
    event_name = evt.get("event")
    if event_name:
        payload = {k: v for k, v in evt.items() if k != "event"}
        broadcast(event_name, payload)


subscribe(_handle_observability_event)


def _api_key_required() -> bool:
    return os.getenv("API_REQUIRE_KEY", "").strip().lower() in {"1", "true", "yes", "on"}


def _configured_api_key() -> str:
    return os.getenv("API_KEY", "").strip() or os.getenv("SSL_SENTINEL_API_KEY", "").strip()


@api.before_request
def require_api_key():
    """Optional API-key gate for company deployments.

    The default stays open for local development/tests, but production can set
    API_REQUIRE_KEY=true and API_KEY=<secret>. Mutating scanner endpoints then
    require X-API-Key or Authorization: Bearer <secret>.
    """
    if not _api_key_required():
        return None
    expected = _configured_api_key()
    if not expected:
        return err("API key enforcement is enabled but API_KEY is not configured", 503)
    supplied = (request.headers.get("X-API-Key") or "").strip()
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        supplied = auth.split(None, 1)[1].strip()
    if hmac.compare_digest(supplied, expected):
        return None
    return err("Unauthorized", 401)


# ── Helpers ───────────────────────────────────────────────────────────────────

def ok(data=None, **kw):
    p = {"ok": True}
    if data is not None: p["data"] = data
    p.update(kw)
    return jsonify(p)


def err(msg, code=400):
    return jsonify({"ok": False, "error": msg}), code


def _normalize_hostname(raw: str) -> str:
    host = normalize_target_hostname(raw)
    if not host or not is_target_allowed(host):
        return ""
    return host



def _analyze_hosts_text(content: str) -> dict:
    """Return normalized host inventory metadata before saving a pasted/uploaded list."""
    raw_items = []
    for line in (content or "").splitlines():
        item = line.split("#", 1)[0].strip()
        if item:
            raw_items.append(item)

    normalized = []
    invalid = []
    seen = set()
    duplicates = []
    for raw in raw_items:
        host = _normalize_hostname(raw)
        if not host:
            invalid.append(raw)
            continue
        if host in seen:
            duplicates.append(host)
            continue
        seen.add(host)
        normalized.append(host)

    return {
        "hosts": normalized,
        "host_count": len(normalized),
        "input_count": len(raw_items),
        "invalid_count": len(invalid),
        "duplicate_count": len(duplicates),
        "invalid_samples": invalid[:25],
        "duplicate_samples": duplicates[:25],
        "scope_domains": allowed_scope_domains(),
        "private_targets_allowed": allow_private_targets(),
    }




BOUNTY_KEYWORD_RULES = [
    ("admin", 20, "Admin surface"),
    ("administrator", 20, "Admin surface"),
    ("login", 14, "Login surface"),
    ("auth", 16, "Authentication surface"),
    ("sso", 18, "SSO surface"),
    ("api", 14, "API surface"),
    ("swagger", 24, "API documentation"),
    ("openapi", 24, "API documentation"),
    ("graphql", 24, "GraphQL surface"),
    ("dev", 16, "Development host"),
    ("test", 14, "Test host"),
    ("stage", 16, "Staging host"),
    ("staging", 16, "Staging host"),
    ("uat", 16, "UAT host"),
    ("internal", 22, "Internal-looking host"),
    ("vpn", 18, "Remote access surface"),
    ("jenkins", 26, "CI/CD surface"),
    ("git", 18, "Source control surface"),
    ("grafana", 24, "Monitoring dashboard"),
    ("kibana", 24, "Logging dashboard"),
    ("prometheus", 22, "Metrics surface"),
    ("metrics", 18, "Metrics surface"),
    ("jira", 18, "Issue tracker"),
    ("confluence", 18, "Knowledge base"),
    ("phpmyadmin", 28, "Database admin surface"),
    ("db", 16, "Database-looking host"),
    ("redis", 18, "Cache/database host"),
    ("elastic", 18, "Search/database host"),
    ("solr", 18, "Search/database host"),
]


def _bounty_lead_severity(score: int) -> str:
    if score >= 75:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def _bounty_lead_next_steps(row: dict, evidence: list[str]) -> list[str]:
    steps = [
        "Confirm this asset is in your authorized bug-bounty scope before testing.",
        "Open the host in a browser and capture status, title, redirects, and screenshots.",
    ]
    joined = " ".join(evidence).lower()
    if "api" in joined or "swagger" in joined or "graphql" in joined:
        steps.append("Check API docs, authentication boundaries, IDOR patterns, and sensitive schema exposure.")
    if "admin" in joined or "dashboard" in joined or "login" in joined:
        steps.append("Test access-control expectations, default credentials only where permitted, and exposed debug panels.")
    if row.get("is_mismatch"):
        steps.append("Investigate whether the certificate mismatch reveals a shared tenant, stale takeover path, or misrouted service.")
    if row.get("http_status_code") in (401, 403):
        steps.append("Look for bypasses, alternate methods, path normalization, and misconfigured reverse-proxy routes.")
    return steps


def _score_bounty_lead(row: dict) -> dict:
    hostname = (row.get("hostname") or "").lower()
    title = (row.get("http_page_title") or "").lower()
    final_url = (row.get("http_final_url") or "").lower()
    score = 0
    evidence: list[str] = []
    lead_types: list[str] = []

    for keyword, points, label in BOUNTY_KEYWORD_RULES:
        if re.search(rf"(^|[.\-_]){re.escape(keyword)}([.\-_]|$)", hostname) or keyword in title or keyword in final_url:
            score += points
            if label not in lead_types:
                lead_types.append(label)
            evidence.append(f"{label}: matched '{keyword}'")

    status = row.get("http_status_code")
    if row.get("http_is_active"):
        score += 20
        evidence.append("HTTP probe marked the host active")
    if status in (200, 204, 301, 302, 307, 308):
        score += 10
        evidence.append(f"Reachable HTTP status {status}")
    elif status in (401, 403):
        score += 18
        evidence.append(f"Protected surface returned HTTP {status}")
    elif isinstance(status, int) and status >= 500:
        score += 12
        evidence.append(f"Server error surface returned HTTP {status}")

    if row.get("is_latest_discovery"):
        score += 15
        evidence.append("New in the latest discovery feed")
        lead_types.append("Fresh discovery")
    if row.get("is_mismatch"):
        score += 22
        evidence.append("TLS hostname mismatch detected")
        lead_types.append("TLS misconfiguration")
    if row.get("is_expired"):
        score += 8
        evidence.append("Expired certificate detected")
    if row.get("error"):
        score += 5
        evidence.append(f"TLS scan error: {row.get('error')}")

    score = max(0, min(100, score))
    if not evidence:
        evidence.append("Discovered subdomain with no high-signal bounty markers yet")
        lead_types.append("Recon candidate")

    return {
        **row,
        "score": score,
        "severity": _bounty_lead_severity(score),
        "lead_type": ", ".join(dict.fromkeys(lead_types)) or "Recon candidate",
        "evidence": evidence[:10],
        "next_steps": _bounty_lead_next_steps(row, evidence),
    }


def _collect_bounty_leads(project_id: str = "", search: str = "", limit: int = 100) -> dict:
    where = ["p.enabled=1", "COALESCE(hx.is_active, 0)=1"]
    params: list = []
    if project_id:
        where.append("p.id=?")
        params.append(project_id)
    if search:
        where.append("LOWER(h.hostname) LIKE ?")
        params.append(f"%{search.lower()}%")
    where_sql = " AND ".join(where)
    rows = db.x(
        f"""
        WITH latest_result AS (
          SELECT r.*
          FROM results r
          JOIN (
            SELECT project_id, hostname, MAX(checked_at) AS checked_at
            FROM results
            GROUP BY project_id, hostname
          ) lr ON lr.project_id=r.project_id AND lr.hostname=r.hostname AND lr.checked_at=r.checked_at
        )
        SELECT
          p.id AS project_id,
          p.name AS project_name,
          h.hostname,
          h.first_seen,
          h.last_seen,
          CASE WHEN EXISTS (
            SELECT 1 FROM subfinder_new_discoveries n
            WHERE n.project_id=h.project_id AND n.hostname=h.hostname
          ) THEN 1 ELSE 0 END AS is_latest_discovery,
          hx.status_code AS http_status_code,
          hx.page_title AS http_page_title,
          hx.redirect_location AS http_redirect_location,
          hx.final_url AS http_final_url,
          hx.scheme AS http_scheme,
          hx.is_active AS http_is_active,
          r.cn,
          r.expiry,
          r.days_left,
          r.is_mismatch,
          r.is_expired,
          r.is_expiring,
          r.error,
          r.checked_at
        FROM subfinder_hosts h
        JOIN projects p ON p.id=h.project_id
        LEFT JOIN subfinder_httpx_results hx ON hx.project_id=h.project_id AND hx.hostname=h.hostname
        LEFT JOIN latest_result r ON r.project_id=h.project_id AND r.hostname=h.hostname
        WHERE {where_sql}
        ORDER BY hx.last_checked DESC, h.first_seen DESC
        LIMIT ?
        """,
        params + [max(1, min(500, limit * 4))],
    ).fetchall()
    leads = [_score_bounty_lead(dict(r)) for r in rows]
    leads.sort(key=lambda r: (r.get("score") or 0, r.get("is_latest_discovery") or 0, r.get("first_seen") or ""), reverse=True)
    selected = leads[:limit]
    return {
        "rows": selected,
        "total": len(leads),
        "returned": len(selected),
        "project_id": project_id,
        "search": search,
        "method": "Ranks authorized Subfinder discoveries after validating host reachability with ProjectDiscovery httpx, then scores active HTTP exposure, high-value host keywords, fresh-discovery status, and TLS anomalies.",
    }


def _collect_bounty_summary(project_id: str = "", search: str = "") -> dict:
    """Build company/program-level attack-surface KPIs from ranked bounty leads."""
    data = _collect_bounty_leads(project_id=project_id, search=search, limit=500)
    rows = data.get("rows", [])
    total = data.get("total", len(rows))
    high = sum(1 for r in rows if r.get("severity") == "high")
    medium = sum(1 for r in rows if r.get("severity") == "medium")
    active = sum(1 for r in rows if r.get("http_is_active"))
    protected = sum(1 for r in rows if r.get("http_status_code") in (401, 403))
    tls_anomalies = sum(1 for r in rows if r.get("is_mismatch") or r.get("is_expired") or r.get("is_expiring"))
    fresh = sum(1 for r in rows if r.get("is_latest_discovery"))

    keyword_counts: dict[str, int] = {}
    project_counts: dict[str, int] = {}
    for r in rows:
        project = r.get("project_name") or "Unassigned"
        project_counts[project] = project_counts.get(project, 0) + 1
        for label in (r.get("lead_type") or "Recon candidate").split(","):
            label = label.strip() or "Recon candidate"
            keyword_counts[label] = keyword_counts.get(label, 0) + 1

    return {
        "total_leads": total,
        "returned": len(rows),
        "high": high,
        "medium": medium,
        "active_http": active,
        "protected_http": protected,
        "tls_anomalies": tls_anomalies,
        "fresh_discoveries": fresh,
        "top_projects": [{"name": k, "count": v} for k, v in sorted(project_counts.items(), key=lambda item: item[1], reverse=True)[:6]],
        "top_surface_types": [{"name": k, "count": v} for k, v in sorted(keyword_counts.items(), key=lambda item: item[1], reverse=True)[:8]],
        "executive_summary": (
            f"{high} high-priority and {medium} medium-priority leads across {total} ranked assets; "
            f"{active} active HTTP surfaces, {protected} protected login/API surfaces, and {tls_anomalies} TLS anomalies need validation."
        ),
    }


BOUNTY_HYPOTHESIS_RULES = [
    {
        "id": "access-control",
        "match": ("admin", "administrator", "login", "dashboard", "sso", "auth"),
        "title": "Access-control and authentication boundary review",
        "tests": [
            "Map login, logout, password reset, invitation, and SSO callback flows.",
            "Validate horizontal and vertical authorization with low-privilege accounts you own.",
            "Check redirects, method overrides, and path normalization for protected routes.",
        ],
        "reporting": "Include affected URL, role matrix, request/response pair, impact, and remediation boundary.",
    },
    {
        "id": "api-exposure",
        "match": ("api", "swagger", "openapi", "graphql"),
        "title": "API/schema exposure and IDOR review",
        "tests": [
            "Enumerate documented endpoints and compare unauthenticated vs authenticated responses.",
            "Probe object identifiers you own for predictable IDs, tenant leaks, and excessive fields.",
            "Review GraphQL introspection, batching, depth, and authorization on nested resolvers where allowed.",
        ],
        "reporting": "Attach schema excerpts, minimal safe proof-of-concept requests, and tenant/user isolation impact.",
    },
    {
        "id": "devops-panel",
        "match": ("jenkins", "git", "grafana", "kibana", "prometheus", "metrics", "jira", "confluence"),
        "title": "DevOps/SaaS panel exposure review",
        "tests": [
            "Confirm whether the panel is intended to be internet-accessible and in bounty scope.",
            "Check unauthenticated metadata, dashboards, version banners, and sensitive project names.",
            "Test only safe read-only access paths; avoid destructive CI/CD, issue-tracker, or monitoring actions.",
        ],
        "reporting": "Document exposed product, access level, screenshots, sensitive metadata, and business impact.",
    },
    {
        "id": "environment-drift",
        "match": ("dev", "test", "stage", "staging", "uat", "internal"),
        "title": "Non-production environment drift review",
        "tests": [
            "Compare headers, auth requirements, and feature flags against production equivalents.",
            "Look for debug output, stack traces, sample credentials, and permissive CORS on owned test accounts.",
            "Validate that staging data is synthetic and does not expose customer or employee information.",
        ],
        "reporting": "Show environment indicator, drift from production controls, and concrete data/control exposure.",
    },
    {
        "id": "tls-routing",
        "match": ("tls", "certificate", "mismatch", "expired"),
        "title": "TLS/routing anomaly review",
        "tests": [
            "Inspect certificate CN/SANs for unrelated tenants, stale brands, or takeover clues.",
            "Compare HTTP Host routing over HTTPS for misdirected default vhosts and stale services.",
            "Check expiry/mismatch impact on authentication, API clients, and sensitive user flows.",
        ],
        "reporting": "Include certificate fingerprint, CN/SAN evidence, affected hostname, and routing impact.",
    },
]


def _lead_keywords(row: dict) -> str:
    return " ".join(str(row.get(k) or "") for k in ("hostname", "lead_type", "http_page_title", "http_final_url", "evidence")).lower()


def _hypotheses_for_leads(leads: list[dict]) -> list[dict]:
    joined = " ".join(_lead_keywords(r) for r in leads)
    selected = []
    for rule in BOUNTY_HYPOTHESIS_RULES:
        if any(token in joined for token in rule["match"]):
            selected.append(rule)
    if not selected:
        selected.append({
            "id": "baseline-recon",
            "title": "Baseline recon and exposure review",
            "tests": [
                "Verify scope, ownership, and safe testing rules before touching any asset.",
                "Capture status, title, redirects, technologies, and screenshots for active hosts.",
                "Prioritize authenticated, high-impact business functionality over noisy automated checks.",
            ],
            "reporting": "Bundle exact URLs, safe reproduction steps, observed impact, and suggested fix.",
        })
    return selected


def _collect_bounty_brief(project_id: str = "", search: str = "", limit: int = 25) -> dict:
    """Build a bug-bounty operator brief from ranked authorized attack-surface leads."""
    leads_data = _collect_bounty_leads(project_id=project_id, search=search, limit=limit)
    leads = leads_data.get("rows", [])
    summary = _collect_bounty_summary(project_id=project_id, search=search)
    critical_path = []
    for idx, lead in enumerate(leads[:10], start=1):
        critical_path.append({
            "rank": idx,
            "hostname": lead.get("hostname"),
            "score": lead.get("score"),
            "severity": lead.get("severity"),
            "why": lead.get("evidence", [])[:4],
            "first_actions": lead.get("next_steps", [])[:3],
        })
    return {
        "generated_at": db.now(),
        "project_id": project_id,
        "search": search,
        "scope_guardrails": [
            "Only test assets that are explicitly authorized by the program or your configured scope.",
            "Prefer low-impact proof-of-concepts; do not run destructive, persistence, spam, or data-exfiltration tests.",
            "Record timestamps, account IDs you own, request IDs, and exact URLs for reproducibility.",
        ],
        "executive_summary": summary.get("executive_summary"),
        "kpis": summary,
        "critical_path": critical_path,
        "hypotheses": _hypotheses_for_leads(leads),
        "report_template": {
            "title": "[Asset] Vulnerability class with concise impact",
            "sections": [
                "Scope and authorization statement",
                "Affected asset(s) and environment",
                "Impact and affected users/data",
                "Safe reproduction steps",
                "Evidence: requests, responses, screenshots, and timestamps",
                "Suggested remediation and validation steps",
            ],
        },
        "method": "Transforms ranked authorized leads into a manual validation plan, hypotheses, and report-ready evidence checklist.",
    }

def _run_openssl_subject(hostname: str, timeout: int = 20) -> dict:
    cmd = ["openssl", "s_client", "-connect", f"{hostname}:443"]
    try:
        run = subprocess.run(
            cmd,
            input="",
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        lines = [ln.strip() for ln in (run.stdout or "").splitlines() if "subject" in ln.lower()]
        subject = lines[0] if lines else ""
        return {
            "hostname": hostname,
            "subject": subject or "subject not found",
            "status": "ok" if subject else "no_subject",
            "exit_code": run.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"hostname": hostname, "subject": "", "status": "timeout", "error": f"timeout after {timeout}s"}
    except FileNotFoundError:
        return {"hostname": hostname, "subject": "", "status": "error", "error": "openssl binary not found"}
    except Exception as e:
        return {"hostname": hostname, "subject": "", "status": "error", "error": str(e)}


def _collect_openssl_hosts(pid: str) -> list[str]:
    base_hosts = {_normalize_hostname(h) for h in db.project_hosts(pid)}
    sf_hosts = {
        _normalize_hostname(r["hostname"])
        for r in db.x("SELECT hostname FROM subfinder_hosts WHERE project_id=?", (pid,)).fetchall()
    }
    return sorted({h for h in (base_hosts | sf_hosts) if h})


def _start_quick_scan(hosts: list[str]) -> str:
    sid = db.uid()
    with _quick_scan_lock:
        _quick_scan_state[sid] = {
            "id": sid,
            "status": "running",
            "source": "quick_scan",
            "total": len(hosts),
            "done": 0,
            "ok": 0,
            "mismatches": 0,
            "expired": 0,
            "expiring": 0,
            "errors": 0,
            "hosts": hosts,
            "rows": [],
            "rows_total": 0,
            "started_at": db.now(),
            "finished_at": None,
        }
    jobs.create_job("quick_scan", id=sid, status="running", total=len(hosts), source="manual", payload={"source": "quick_scan", "hosts": hosts})
    th = threading.Thread(target=_quick_scan_worker, args=(sid,), daemon=True, name=f"quick-scan-{sid[:8]}")
    with _quick_scan_lock:
        _quick_scan_threads[sid] = th
    th.start()
    return sid


def _quick_scan_worker(sid: str):
    from core.ssl_checker import run_checker

    with _quick_scan_lock:
        state = _quick_scan_state.get(sid)
        hosts = list(state.get("hosts") or []) if state else []
    if not hosts:
        with _quick_scan_lock:
            if sid in _quick_scan_state:
                _quick_scan_state[sid]["status"] = "error"
                _quick_scan_state[sid]["finished_at"] = db.now()
        return

    def _on_result(done: int, total: int, row: dict):
        row = dict(row or {})
        row.setdefault("hostname", "")
        row.setdefault("cn", "")
        row.setdefault("issuer", "")
        row.setdefault("expiry", "")
        row.setdefault("days_left", None)
        row["is_expiring"] = bool(row.get("is_expiring_soon"))
        with _quick_scan_lock:
            state = _quick_scan_state.get(sid)
            if not state:
                return
            state["rows"].append(row)
            state["rows_total"] = int(state.get("rows_total") or 0) + 1
            if len(state["rows"]) > QUICK_SCAN_ROWS_BUFFER:
                state["rows"] = state["rows"][-QUICK_SCAN_ROWS_BUFFER:]
            state["done"] = done
            state["ok"] += 1 if row.get("is_ok") else 0
            state["mismatches"] += 1 if row.get("is_mismatch") else 0
            state["expired"] += 1 if row.get("is_expired") else 0
            state["expiring"] += 1 if row.get("is_expiring_soon") else 0
            state["errors"] += 1 if row.get("error") else 0
            payload = {
                "id": sid,
                "status": "running",
                "total": total,
                "done": done,
                "ok": state["ok"],
                "mismatches": state["mismatches"],
                "expired": state["expired"],
                "expiring": state["expiring"],
                "errors": state["errors"],
            }
        jobs.update_progress(sid, done=done, total=total, ok=payload["ok"], mismatches=payload["mismatches"], expired=payload["expired"], expiring=payload["expiring"], errors=payload["errors"])
        broadcast("quick_scan_row", {"scan_id": sid, "row": row})
        broadcast("quick_scan_update", payload)

    try:
        # Quick scans run on-demand and often from low-resource dynos/containers.
        # Keep worker count conservative to avoid "can't start new thread" and
        # premature scan termination a few seconds after start.
        quick_workers = max(4, min(32, len(hosts)))
        run_checker(
            hosts,
            max_workers=quick_workers,
            progress_callback=_on_result,
            collect_results=False,
        )
        with _quick_scan_lock:
            state = _quick_scan_state.get(sid)
            if state:
                state["status"] = "done"
                state["finished_at"] = db.now()
                state["hosts"] = []
                payload = {
                    "id": sid,
                    "status": "done",
                    "total": state["total"],
                    "done": state["done"],
                    "ok": state["ok"],
                    "mismatches": state["mismatches"],
                    "expired": state["expired"],
                    "expiring": state["expiring"],
                    "errors": state["errors"],
                    "finished_at": state["finished_at"],
                }
        jobs.update_state(sid, status="done", done=payload.get("done", 0), progress=payload.get("done", 0), finished_at=payload.get("finished_at"))
        broadcast("quick_scan_update", payload)
    except Exception as e:
        with _quick_scan_lock:
            state = _quick_scan_state.get(sid)
            if state:
                state["status"] = "error"
                state["error"] = str(e)
                state["finished_at"] = db.now()
                state["hosts"] = []
                payload = {
                    "id": sid,
                    "status": "error",
                    "error": str(e),
                    "total": state["total"],
                    "done": state["done"],
                }
        jobs.update_state(sid, status="error", finished_at=payload.get("finished_at") if 'payload' in locals() else db.now(), payload={"error": str(e)})
        broadcast("quick_scan_update", payload)


def _start_openssl_worker(pid: str, source: str = "manual") -> bool:
    with _openssl_lock:
        existing = _openssl_threads.get(pid)
        if existing and existing.is_alive():
            return False
        job = jobs.create_job("openssl_scan", id=f"openssl:{pid}", project_id=pid, status="running", source=source, payload={})
        _openssl_status[pid] = {
            "status": "running",
            "source": source,
            "started_at": time.time(),
            "last_tick": time.time(),
            "processed_total": 0,
            "new_hosts_scanned": 0,
        }
        th = threading.Thread(target=_openssl_worker_loop, args=(pid, source), daemon=True, name=f"openssl-{pid[:8]}")
        _openssl_threads[pid] = th
        th.start()
        return True


def _openssl_worker_loop(pid: str, source: str):
    try:
        while True:
            if not db.project_get(pid):
                break
            known = {r["hostname"] for r in db.openssl_results_list(pid, limit=5000)}
            hosts = _collect_openssl_hosts(pid)
            pending = [h for h in hosts if h not in known]

            with _openssl_lock:
                if pid in _openssl_status:
                    _openssl_status[pid]["last_tick"] = time.time()

            if not pending:
                broadcast("openssl_status", {"project_id": pid, "status": "idle_waiting", "tracked_hosts": len(hosts)})
                time.sleep(10)
                continue

            rows = []
            for hostname in pending:
                row = _run_openssl_subject(hostname)
                rows.append(row)
                db.openssl_results_upsert_batch(pid, [row], source=source)
                with _openssl_lock:
                    if pid in _openssl_status:
                        _openssl_status[pid]["processed_total"] += 1
                        _openssl_status[pid]["new_hosts_scanned"] += 1
                        jobs.update_progress(f"openssl:{pid}", done=_openssl_status[pid]["processed_total"], new_hosts_scanned=_openssl_status[pid]["new_hosts_scanned"])
                broadcast("openssl_row", {"id": f"openssl:{pid}", "project_id": pid, "row": row})

            broadcast("openssl_status", {
                "project_id": pid,
                "status": "running",
                "processed": len(rows),
                "pending_after": 0,
                "tracked_hosts": len(hosts),
            })
            time.sleep(2)
    finally:
        with _openssl_lock:
            if pid in _openssl_status:
                _openssl_status[pid]["status"] = "stopped"
        broadcast("openssl_status", {"project_id": pid, "status": "stopped"})


# ── SSE stream ────────────────────────────────────────────────────────────────

@api.get("/sse")
def sse_stream():
    """
    Server-Sent Events endpoint. Browser connects once and receives live events:
      - alert_update: {unseen_count}
      - scan_update:  {scan_id, progress, total, status}
      - stats_update: {mismatches, expired, ...}
    """
    q = queue.Queue(maxsize=50)
    with _sse_lock:
        _sse_clients.append(q)

    def generate():
        last_event_id = _safe_int(request.headers.get("Last-Event-ID") or request.args.get("last_event_id"), 0, min_value=0)
        yield f"event: connected\nid: {last_event_id}\ndata: {{}}\n\n"
        try:
            for evt in jobs.events_since(last_event_id, limit=200):
                yield f"event: {evt['event']}\nid: {evt['rowid']}\ndata: {json.dumps(evt.get('payload') or {})}\n\n"
            while True:
                try:
                    msg = q.get(timeout=25)
                    yield msg
                except queue.Empty:
                    # Heartbeat to keep connection alive (Railway times out at 30s)
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                if q in _sse_clients:
                    _sse_clients.remove(q)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering
        }
    )


# ── Projects ──────────────────────────────────────────────────────────────────

@api.get("/projects")
def list_projects():
    projects = db.project_list()
    for p in projects:
        p["latest_scan"] = db.scan_latest(p["id"])
    return ok(projects)


@api.post("/projects")
def create_project():
    d = request.json or {}
    name = (d.get("name") or "").strip()
    if not name:
        return err("name is required")
    if db.project_get_by_name(name):
        return err("A project with that name already exists")
    p = db.project_create(
        name,
        d.get("description", ""),
        _safe_int(d.get("scan_interval", 60), 60, min_value=5, max_value=10080),
        _safe_int(d.get("subfinder_interval", 30), 30, min_value=5, max_value=10080),
    )
    broadcast("project_created", {"id": p["id"], "name": p["name"]})
    return ok(p)


@api.get("/projects/<pid>")
def get_project(pid):
    p = db.project_get(pid)
    if not p: return err("Not found", 404)
    p["latest_scan"] = db.scan_latest(pid)
    return ok(p)


@api.put("/projects/<pid>")
def update_project(pid):
    d = request.json or {}
    allowed = {"name","description","scan_interval_minutes","subfinder_interval_minutes",
               "subfinder_enabled","enabled"}
    kw = {k: v for k, v in d.items() if k in allowed}
    db.project_update(pid, **kw)
    return ok(db.project_get(pid))


@api.delete("/projects/<pid>")
def delete_project(pid):
    db.project_delete(pid)
    broadcast("project_deleted", {"id": pid})
    return ok()


@api.post("/projects/<pid>/hosts")
def upload_hosts(pid):
    if not db.project_get(pid):
        return err("Project not found", 404)
    if "file" in request.files:
        content = request.files["file"].read().decode("utf-8", errors="ignore")
    else:
        content = (request.json or {}).get("hosts", "") or (request.data or b"").decode()
    analysis = _analyze_hosts_text(content)
    hosts = analysis["hosts"]
    if not hosts:
        return err("No valid hostnames found")
    db.project_save_hosts(pid, hosts)
    return ok({"count": len(hosts), "analysis": analysis})


@api.get("/projects/<pid>/hosts")
def get_hosts(pid):
    return ok(db.project_hosts(pid))


@api.post("/projects/<pid>/hosts/preview")
def preview_hosts(pid):
    if not db.project_get(pid):
        return err("Project not found", 404)
    content = (request.json or {}).get("hosts", "") or (request.data or b"").decode(errors="ignore")
    return ok(_analyze_hosts_text(content))


# ── Scans ─────────────────────────────────────────────────────────────────────

@api.post("/projects/<pid>/scan")
def trigger_scan(pid):
    p = db.project_get(pid)
    if not p: return err("Project not found", 404)
    if int(p.get("host_count") or 0) <= 0:
        return err("Upload a host list first")
    if not run_project_scan_async(pid, triggered_by="manual"):
        return err("A scan is already running for this project")
    return ok({"message": "Scan started"})


@api.get("/projects/<pid>/scans")
def list_scans(pid):
    return ok(db.scan_list(pid))


@api.get("/scans/<sid>")
def get_scan(sid):
    s = db.scan_get(sid)
    if not s: return err("Not found", 404)
    live = get_scan_state(sid)
    if live:
        s["live_progress"] = live.get("progress", 0)
        s["live_status"] = live.get("status")
    return ok(s)


@api.get("/assets")
def assets_list():
    project_id = request.args.get("project_id", "").strip()
    search = request.args.get("search", "").strip()
    page = _safe_int(request.args.get("page", 1), 1, min_value=1)
    per_page = _safe_int(request.args.get("per_page", 100), 100, min_value=1, max_value=500)
    if project_id:
        db.asset_backfill_project(project_id)
    return ok(db.assets_list(project_id=project_id, search=search, page=page, per_page=per_page))


@api.get("/assets/<asset_id>")
def asset_detail(asset_id):
    asset = db.asset_get(asset_id)
    if not asset:
        return err("Asset not found", 404)
    return ok(asset)


@api.get("/assets/<asset_id>/relationships")
def asset_relationships(asset_id):
    if not db.asset_get(asset_id):
        return err("Asset not found", 404)
    return ok({"relationships": db.asset_relationships_get(asset_id)})


@api.get("/scans/<sid>/results")
def get_results(sid):
    flt = request.args.get("filter", "all")
    page = _safe_int(request.args.get("page", 1), 1, min_value=1)
    per_page = _safe_int(request.args.get("per_page", 500), 500, min_value=50, max_value=1000)
    return ok(db.results_get(sid, flt, page, per_page))


@api.get("/scans/<sid>/results/export")
def export_results(sid):
    scan = db.scan_get(sid)
    if not scan:
        return err("Scan not found", 404)
    flt = (request.args.get("filter", "all") or "all").strip().lower()
    if flt not in {"all", "mismatch", "expired", "expiring", "ok", "errors"}:
        return err("Invalid filter", 400)
    rows = db.scan_results_all(sid, flt)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([
        "hostname", "status", "cn", "issuer", "not_before", "expiry", "days_left",
        "tls_version", "cipher_suite", "cipher_bits", "key_algorithm", "key_bits",
        "signature_algorithm", "san_count", "fingerprint_sha256", "serial_number", "error", "checked_at",
    ])
    for r in rows:
        writer.writerow([
            r.get("hostname", ""), _result_status(r), r.get("cn", ""), r.get("issuer", ""),
            r.get("not_before", ""), r.get("expiry", ""), r.get("days_left", ""),
            r.get("tls_version", ""), r.get("cipher_suite", ""), r.get("cipher_bits", ""),
            r.get("key_algorithm", ""), r.get("key_bits", ""), r.get("signature_algorithm", ""),
            r.get("san_count", ""), r.get("fingerprint_sha256", ""), r.get("serial_number", ""),
            r.get("error", ""), r.get("checked_at", ""),
        ])
    filename = f"ssl-scan-{sid[:8]}-{flt}.csv"
    return Response(
        out.getvalue(),
        content_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _result_status(row: dict) -> str:
    if row.get("error"):
        return "error"
    if row.get("is_expired"):
        return "expired"
    if row.get("is_mismatch"):
        return "mismatch"
    if row.get("is_expiring") or row.get("is_expiring_soon"):
        return "expiring"
    if row.get("is_ok"):
        return "ok"
    return "unknown"


@api.get("/scans/<sid>/compare")
def compare_scan(sid):
    if not db.scan_get(sid):
        return err("Scan not found", 404)
    previous_sid = (request.args.get("previous_scan_id") or "").strip() or None
    comparison = db.scan_compare(sid, previous_sid)
    if comparison is None:
        return err("Scan not found", 404)
    return ok(comparison)


@api.get("/active-scans")
def active_scans():
    return ok(list_active_scans())


@api.post("/scans/<sid>/pause")
def pause_scan_route(sid):
    if not db.scan_get(sid):
        return err("Scan not found", 404)
    if not pause_scan(sid):
        return err("Scan is not running", 409)
    live = get_scan_state(sid) or {"id": sid, "status": "paused"}
    db.scan_update(sid, status="paused")
    broadcast("scan_update", {"id": sid, **live, "status": "paused"})
    return ok({"scan_id": sid, "status": "paused"})


@api.post("/scans/<sid>/resume")
def resume_scan_route(sid):
    if not db.scan_get(sid):
        return err("Scan not found", 404)
    if not resume_scan(sid):
        return err("Scan is not paused", 409)
    live = get_scan_state(sid) or {"id": sid, "status": "running"}
    db.scan_update(sid, status="running")
    broadcast("scan_update", {"id": sid, **live, "status": "running"})
    return ok({"scan_id": sid, "status": "running"})


@api.post("/scans/<sid>/stop")
def stop_scan_route(sid):
    if not db.scan_get(sid):
        return err("Scan not found", 404)
    if not stop_scan(sid):
        return err("Scan is not active", 409)
    live = get_scan_state(sid) or {"id": sid, "status": "stopping"}
    db.scan_update(sid, status="stopping")
    broadcast("scan_update", {"id": sid, **live, "status": "stopping"})
    return ok({"scan_id": sid, "status": "stopping"})


@api.post("/quick-scan")
def start_quick_scan():
    d = request.json or {}
    hosts_raw = d.get("hosts", "") or ""
    hosts = parse_hosts_file(hosts_raw)
    hosts = sorted({_normalize_hostname(h) for h in hosts if _normalize_hostname(h)})
    if not hosts:
        return err("Paste at least one valid hostname")
    if len(hosts) > 50000:
        return err("Quick scan supports up to 50000 hosts at once")
    sid = _start_quick_scan(hosts)
    return ok({"scan_id": sid, "total": len(hosts), "status": "running"})


@api.get("/quick-scan/<sid>")
def quick_scan_status(sid):
    with _quick_scan_lock:
        state = dict(_quick_scan_state.get(sid) or {})
    if not state:
        job = jobs.get_job(sid)
        if job:
            state = jobs.public_state(job)
    if not state:
        return err("Quick scan not found", 404)
    # Keep status payload tiny so polling remains fast even for large scans.
    state.pop("rows", None)
    state.pop("hosts", None)
    return ok(state)


# ── Alerts ────────────────────────────────────────────────────────────────────

@api.get("/alerts")
def get_alerts():
    search = (request.args.get("search", "") or "").strip()
    mismatch = (request.args.get("mismatch_scope", "all") or "all").strip()
    project_id = (request.args.get("project_id", "") or "").strip()
    page = _safe_int(request.args.get("page", 1), 1, min_value=1)
    per_page = _safe_int(request.args.get("per_page", 200), 200, min_value=50, max_value=1000)
    return ok(db.alerts_get(search=search, mismatch_scope=mismatch, project_id=project_id, page=page, per_page=per_page))


@api.post("/alerts/<aid>/read")
def mark_one_seen(aid):
    db.alert_mark_seen(aid)
    broadcast("alert_update", {"unseen_count": db.alerts_unseen_count()})
    return ok()


@api.post("/alerts/seen")
def mark_seen():
    db.alerts_mark_all_seen()
    # Push SSE so badge resets instantly in all open tabs
    broadcast("alert_update", {"unseen_count": 0})
    return ok()


@api.post("/alerts/clear")
def clear_alerts():
    db.alerts_clear()
    # Push SSE — this is what was missing causing the stale counter bug
    broadcast("alert_update", {"unseen_count": 0})
    return ok()


@api.get("/alert-settings")
def get_alert_settings():
    return ok(db.alert_settings_get())


@api.put("/alert-settings")
def update_alert_settings():
    d = request.json or {}
    previous = db.alert_settings_get()
    try:
        slack_webhook_url = _validate_webhook_url((d.get("slack_webhook_url") or "").strip())
        discord_webhook_url = _validate_webhook_url((d.get("discord_webhook_url") or "").strip())
    except ValueError as e:
        return err(str(e), 400)

    cleaned = {
        "telegram_enabled": d.get("telegram_enabled"),
        "telegram_bot_token": (d.get("telegram_bot_token") or "").strip(),
        "telegram_chat_id": (d.get("telegram_chat_id") or "").strip(),
        "slack_enabled": d.get("slack_enabled"),
        "slack_webhook_url": slack_webhook_url,
        "discord_enabled": d.get("discord_enabled"),
        "discord_webhook_url": discord_webhook_url,
        "rule_mismatch": d.get("rule_mismatch"),
        "rule_expired": d.get("rule_expired"),
        "rule_expiring": d.get("rule_expiring"),
        "rule_error": d.get("rule_error"),
        "mismatch_scope_filter": (d.get("mismatch_scope_filter") or "all").strip(),
        "minimum_days_left": _safe_int(d.get("minimum_days_left", 30), 30, min_value=1, max_value=365),
    }
    out = db.alert_settings_update(**cleaned)

    # Immediately smoke-test enabled channels so broken settings are visible at save-time.
    channel_checks = {}
    sample_alert = [{
        "hostname": "example.com",
        "issue_type": "SSL Mismatch",
        "details": "CN 'wrong.example.com' ≠ hostname",
    }]
    if bool(out.get("slack_enabled")) and (out.get("slack_webhook_url") or "").strip():
        channel_checks["slack"] = bool(
            WebhookNotifier("slack", True, out.get("slack_webhook_url", "")).send_mismatch_digest(
                "Settings Test",
                sample_alert,
            )
        )
    if bool(out.get("discord_enabled")) and (out.get("discord_webhook_url") or "").strip():
        channel_checks["discord"] = bool(
            WebhookNotifier("discord", True, out.get("discord_webhook_url", "")).send_mismatch_digest(
                "Settings Test",
                sample_alert,
            )
        )
    if bool(out.get("telegram_enabled")) and (out.get("telegram_bot_token") or "").strip() and (out.get("telegram_chat_id") or "").strip():
        channel_checks["telegram"] = bool(TelegramNotifier(out).send_mismatch_digest("Settings Test", sample_alert))

    failed_channels = [name for name, passed in channel_checks.items() if not passed]
    if failed_channels:
        return err(f"Saved, but webhook test failed for: {', '.join(failed_channels)}", 400)

    discord_turned_on = bool(out.get("discord_enabled")) and not bool(previous.get("discord_enabled"))
    discord_webhook_changed = (out.get("discord_webhook_url") or "") != (previous.get("discord_webhook_url") or "")
    if bool(out.get("discord_enabled")) and (discord_turned_on or discord_webhook_changed):
        # Re-queue existing unresolved alerts so a newly enabled/updated Discord webhook
        # can receive them on the next scan dispatch.
        db.alerts_mark_all_unsent()
    return ok(out, channel_checks=channel_checks)


# ── Stats ─────────────────────────────────────────────────────────────────────

@api.get("/stats")
def global_stats():
    return ok(db.stats_global())


def _collect_attack_surface_risk() -> dict:
    """Return an operator-ready risk rollup for the dashboard."""
    stats = db.stats_global()
    projects = db.project_list()
    bounty = _collect_bounty_summary()
    total_hosts = max(1, int(stats.get("total_domains") or stats.get("domains") or stats.get("hosts") or 0))
    anomaly_count = sum(int(stats.get(k) or 0) for k in ("mismatches", "expired", "errors"))
    stale_projects = sum(1 for p in projects if not db.scan_latest(p["id"]))
    risk_score = min(100, round(
        (anomaly_count / total_hosts) * 70
        + (int(stats.get("unseen_alerts") or 0) / total_hosts) * 20
        + ((stale_projects / max(1, len(projects))) * 10)
    ))
    if risk_score >= 75:
        posture = "critical"
    elif risk_score >= 50:
        posture = "high"
    elif risk_score >= 25:
        posture = "moderate"
    else:
        posture = "low"
    return {
        "risk_score": risk_score,
        "posture": posture,
        "anomaly_count": anomaly_count,
        "stale_projects": stale_projects,
        "bounty_summary": bounty,
        "recommended_actions": [
            "Validate high-priority bounty leads before broad automated scanning.",
            "Run Subfinder on stale projects to refresh scope and discovery evidence.",
            "Triage TLS mismatches and expired certificates for tenant-routing or takeover clues.",
        ],
    }


@api.get("/attack-surface/risk")
def attack_surface_risk():
    return ok(_collect_attack_surface_risk())


@api.get("/bounty/summary")
def bounty_summary():
    project_id = (request.args.get("project_id") or "").strip()
    search = (request.args.get("search") or "").strip()
    return ok(_collect_bounty_summary(project_id=project_id, search=search))


@api.get("/bounty/leads")
def bounty_leads():
    project_id = (request.args.get("project_id") or "").strip()
    search = (request.args.get("search") or "").strip()
    limit = _safe_int(request.args.get("limit", 100), 100, min_value=1, max_value=500)
    return ok(_collect_bounty_leads(project_id=project_id, search=search, limit=limit))


@api.get("/bounty/brief")
def bounty_brief():
    project_id = (request.args.get("project_id") or "").strip()
    search = (request.args.get("search") or "").strip()
    limit = _safe_int(request.args.get("limit", 25), 25, min_value=1, max_value=100)
    return ok(_collect_bounty_brief(project_id=project_id, search=search, limit=limit))


@api.get("/bounty/leads/export")
def bounty_leads_export():
    project_id = (request.args.get("project_id") or "").strip()
    search = (request.args.get("search") or "").strip()
    limit = _safe_int(request.args.get("limit", 500), 500, min_value=1, max_value=500)
    data = _collect_bounty_leads(project_id=project_id, search=search, limit=limit)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["score", "severity", "project", "hostname", "lead_type", "http_status", "title", "final_url", "evidence", "next_steps"])
    for row in data.get("rows", []):
        writer.writerow([
            row.get("score", ""),
            row.get("severity", ""),
            row.get("project_name", ""),
            row.get("hostname", ""),
            row.get("lead_type", ""),
            row.get("http_status_code", ""),
            row.get("http_page_title", ""),
            row.get("http_final_url", ""),
            " | ".join(row.get("evidence") or []),
            " | ".join(row.get("next_steps") or []),
        ])
    return Response(
        out.getvalue(),
        content_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=bounty-leads.csv"},
    )


@api.get("/security-policy")
def security_policy():
    return ok({
        "api_key_required": _api_key_required(),
        "api_key_configured": bool(_configured_api_key()),
        "allowed_scope_domains": allowed_scope_domains(),
        "private_targets_allowed": allow_private_targets(),
        "scope_enforced": bool(allowed_scope_domains()),
    })



@api.get("/system-overview")
def system_overview():
    projects_total = db.x("SELECT COUNT(*) c FROM projects").fetchone()["c"]
    enabled_projects = db.x("SELECT COUNT(*) c FROM projects WHERE enabled=1").fetchone()["c"]
    scans_running = db.x("SELECT COUNT(*) c FROM scans WHERE status='running'").fetchone()["c"]
    latest_scan = db.x("SELECT started_at, status, project_id FROM scans ORDER BY created_at DESC LIMIT 1").fetchone()
    host_inventory = db.x("SELECT COALESCE(SUM(host_count), 0) c FROM projects").fetchone()["c"]
    discoveries = db.x("SELECT COUNT(*) c FROM subfinder_hosts").fetchone()["c"]
    unresolved_alerts = db.x("SELECT COUNT(*) c FROM alerts WHERE seen=0").fetchone()["c"]
    db_file = db.DB_PATH
    uptime_seconds = max(0, int(time.time() - STARTED_AT_TS))
    return ok({
        "uptime_seconds": uptime_seconds,
        "projects_total": projects_total,
        "enabled_projects": enabled_projects,
        "scans_running": scans_running,
        "host_inventory": host_inventory,
        "discoveries_total": discoveries,
        "unresolved_alerts": unresolved_alerts,
        "latest_scan": dict(latest_scan) if latest_scan else None,
        "database": {
            "path": str(db_file),
            "exists": db_file.exists(),
            "size_bytes": db_file.stat().st_size if db_file.exists() else 0,
        },
    })

@api.get("/logs")
def list_logs():
    limit = _safe_int(request.args.get("limit", 200), 200, min_value=20, max_value=1000)
    return ok(get_logs(limit))


# ── Subfinder ─────────────────────────────────────────────────────────────────

@api.post("/projects/<pid>/subfinder/run")
def run_subfinder(pid):
    from subfinder.runner import run_subfinder_async, subfinder_available
    if not pid or pid in {"undefined", "null"}:
        return err("Please select a project before running scan")
    p = db.project_get(pid)
    if not p: return err("Project not found", 404)
    if not db.project_hosts(pid):
        return err("Add a host list first so subfinder knows which root domains to enumerate")
    started = run_subfinder_async(pid, triggered_by="manual")
    if not started:
        return err("Subfinder already running for this project")
    return ok({
        "message": "Subfinder started",
        "binary_found": subfinder_available()
    })


@api.get("/projects/<pid>/subfinder/status")
def subfinder_status(pid):
    from subfinder.runner import get_sf_state, subfinder_available
    return ok({
        "state": get_sf_state(pid),
        "binary_available": subfinder_available(),
        "jobs": db.subfinder_jobs_list(pid, limit=10)
    })


@api.get("/projects/<pid>/subfinder/hosts")
def subfinder_hosts(pid):
    page = _safe_int(request.args.get("page", 1), 1, min_value=1)
    per_page = _safe_int(request.args.get("per_page", 500), 500, min_value=50, max_value=1000)
    return ok(db.subfinder_hosts_list(pid, page, per_page))


@api.get("/projects/<pid>/subfinder/raw-results")
def subfinder_raw_results(pid):
    limit = _safe_int(request.args.get("limit", 20), 20, min_value=1, max_value=100)
    preview_chars = _safe_int(request.args.get("preview_chars", 4000), 4000, min_value=500, max_value=12000)
    return ok(db.subfinder_raw_results_list(pid, limit=limit, preview_chars=preview_chars))


@api.post("/subfinder/enumeration/run")
def run_domain_enumeration():
    from subfinder.runner import run_domain_enumeration_scan
    payload = request.get_json(silent=True) or {}
    domain = (
        payload.get("domain")
        or payload.get("root_domain")
        or request.form.get("domain")
        or request.values.get("domain")
        or request.args.get("domain")
        or ""
    ).strip().lower()
    if not domain:
        return err("Domain is required")
    domain = normalize_target_hostname(domain)
    if not domain:
        return err("Domain must be a valid public hostname", 400)
    root_domain = registered_domain(domain)
    if not is_target_allowed(root_domain):
        return err("Domain is outside configured scan scope or targets a disallowed network", 403)
    try:
        data = run_domain_enumeration_scan(root_domain, triggered_by="manual")
        return ok(data)
    except ValueError as ve:
        return err(str(ve))
    except Exception as e:
        return err(f"Enumeration failed: {e}", 500)


@api.get("/subfinder/enumeration/scans")
def list_domain_enumeration_scans():
    return ok(db.domain_enum_scans_list())


@api.get("/subfinder/enumeration/scans/<scan_id>")
def domain_enumeration_scan_detail(scan_id):
    scan = db.domain_enum_scan_get(scan_id)
    if not scan:
        return err("Not found", 404)
    return ok({"scan": scan, "results": db.domain_enum_results_by_scan(scan_id)})


@api.post("/subfinder/enumeration/scans/<scan_id>/project")
def domain_enumeration_scan_create_project(scan_id):
    scan = db.domain_enum_scan_get(scan_id)
    if not scan:
        return err("Not found", 404)

    rows = db.domain_enum_results_by_scan(scan_id)
    hosts = sorted({
        host for host in (_normalize_hostname(r.get("hostname") or "") for r in rows)
        if host
    })
    if not hosts:
        return err("No in-scope hosts found in this enumeration scan", 400)

    payload = request.get_json(silent=True) or {}
    project_name = (payload.get("name") or payload.get("project_name") or f"Enum {scan.get('domain', '')}").strip()
    if not project_name:
        return err("Project name is required", 400)
    if db.project_get_by_name(project_name):
        return err("A project with that name already exists", 400)

    p = db.project_create(
        project_name,
        payload.get("description", f"Created from enumeration scan {scan_id[:8]} for {scan.get('domain', '')}"),
        _safe_int(payload.get("scan_interval", 60), 60, min_value=5, max_value=10080),
        _safe_int(payload.get("subfinder_interval", 30), 30, min_value=5, max_value=10080),
    )
    db.project_save_hosts(p["id"], hosts)
    broadcast("project_created", {"id": p["id"], "name": p["name"]})
    return ok({"project": db.project_get(p["id"]), "host_count": len(hosts), "scan_id": scan_id})


@api.delete("/subfinder/enumeration/scans/<scan_id>")
def domain_enumeration_scan_delete(scan_id):
    scan = db.domain_enum_scan_get(scan_id)
    if not scan:
        return err("Not found", 404)
    db.domain_enum_scan_delete(scan_id)
    return ok({"deleted": True, "scan_id": scan_id})


@api.get("/subfinder/enumeration/scans/<scan_id>/export")
def domain_enumeration_scan_export(scan_id):
    from subfinder.runner import _resolve_active_hosts_with_httpx

    scan = db.domain_enum_scan_get(scan_id)
    if not scan:
        return err("Not found", 404)
    export_format = (request.args.get("format") or "txt").strip().lower()
    rows = db.domain_enum_results_by_scan(scan_id)
    hosts = [r.get("hostname", "") for r in rows if r.get("hostname")]
    if export_format == "txt":
        payload = "\n".join(sorted(set(hosts))) + ("\n" if hosts else "")
        return Response(
            payload,
            content_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename={scan.get('domain','scan')}-{scan_id[:8]}.txt"},
        )
    if export_format != "csv":
        return err("format must be either txt or csv")

    enrich = _resolve_active_hosts_with_httpx(hosts)
    enrich_map = {r.get("hostname"): r for r in enrich if r.get("hostname")}

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["domain", "subdomain", "source", "discovered_at", "status_code", "scheme", "final_url", "page_title", "is_active", "technologies"])
    for row in rows:
        hx = enrich_map.get(row.get("hostname"), {})
        writer.writerow([
            scan.get("domain", ""),
            row.get("hostname", ""),
            row.get("source", ""),
            row.get("discovered_at", ""),
            hx.get("status_code", ""),
            hx.get("scheme", ""),
            hx.get("final_url", ""),
            hx.get("page_title", ""),
            "yes" if hx.get("is_active") else "no",
            "",
        ])
    return Response(
        out.getvalue(),
        content_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={scan.get('domain','scan')}-{scan_id[:8]}.csv"},
    )


@api.get("/projects/<pid>/discoveries")
def project_discoveries(pid):
    page = _safe_int(request.args.get("page", 1), 1, min_value=1)
    per_page = _safe_int(request.args.get("per_page", 200), 200, min_value=50, max_value=1000)
    search = (request.args.get("search", "") or "").strip()
    mode = (request.args.get("mode", "all") or "all").strip().lower()
    return ok(db.subfinder_discoveries(pid, page, per_page, search, mode=mode))


@api.put("/projects/<pid>/subfinder/toggle")
def toggle_subfinder(pid):
    p = db.project_get(pid)
    if not p: return err("Not found", 404)
    new_val = 0 if p.get("subfinder_enabled") else 1
    db.project_update(pid, subfinder_enabled=new_val)
    return ok({"subfinder_enabled": new_val})




def _resolve_nuclei_hosts(pid: str, mode: str) -> list[str]:
    if mode == "all_subdomains":
        hosts = {_normalize_nuclei_target(h or "") for h in db.project_hosts(pid)}
        rows = db.x("SELECT hostname FROM subfinder_hosts WHERE project_id=?", (pid,)).fetchall()
        hosts |= {_normalize_nuclei_target(r["hostname"] or "") for r in rows}
        return sorted(h for h in hosts if h)

    hosts_data = db.subfinder_discoveries(pid, page=1, per_page=5000, search="", mode="latest")
    return sorted({
        target for target in (_normalize_nuclei_target(r.get("hostname") or "") for r in (hosts_data.get("rows") or []))
        if target
    })


def _nuclei_command(nuclei_bin: str, targets_file: str, templates_dir: str) -> list[str]:
    resources = _nuclei_resource_settings()
    cmd = [
        nuclei_bin,
        "-l", targets_file,
        "-severity", "medium,high,critical",
        "-jsonl",
        "-stats",
    ]
    for optional_flag in ("-stats-json", "-duc", "-no-color", "-silent"):
        if _nuclei_supports_flag(nuclei_bin, optional_flag):
            cmd.append(optional_flag)
    if _nuclei_supports_flag(nuclei_bin, "-ud"):
        cmd.extend(["-ud", templates_dir])
    cmd.extend([
        "-t", templates_dir,
        "-rl", str(resources["rate_limit"]),
        "-c", str(resources["concurrency"]),
        "-bs", str(resources["bulk_size"]),
        "-timeout", str(resources["timeout"]),
    ])
    return cmd


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text or "")


def _looks_like_nuclei_finding(row: dict) -> bool:
    if not isinstance(row, dict):
        return False
    return any(key in row for key in ("template-id", "template_id", "template", "matched-at", "matched_at")) and isinstance(row.get("info"), dict)


def _coerce_nuclei_number(value):
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    text = str(value).strip().replace(",", "")
    if not text:
        return None
    if text.endswith("%"):
        text = text[:-1].strip()
    try:
        number = float(text)
    except ValueError:
        return value
    return int(number) if number.is_integer() else number


def _normalise_nuclei_stats(raw: dict | None, source_line: str = "") -> dict | None:
    if not isinstance(raw, dict):
        return None
    aliases = {
        "templates": ("templates", "template", "templates_total", "total_templates"),
        "hosts": ("hosts", "host", "targets", "target", "total_hosts"),
        "requests": ("requests", "request", "req", "total_requests", "requests_sent"),
        "matched": ("matched", "matches", "findings", "results"),
        "errors": ("errors", "error", "failed", "failures"),
        "rps": ("rps", "req_per_second", "requests_per_second"),
        "duration": ("duration", "elapsed", "elapsed_time"),
        "percent": ("percent", "percentage", "progress"),
    }
    stats = {"raw": raw.copy(), "last_line": _strip_ansi(source_line).strip()}
    lower = {str(k).lower().replace("-", "_").replace(" ", "_"): v for k, v in raw.items()}
    for canonical, keys in aliases.items():
        for key in keys:
            key = key.lower().replace("-", "_").replace(" ", "_")
            if key in lower:
                stats[canonical] = _coerce_nuclei_number(lower[key])
                break
    if "percent" in stats and isinstance(stats["percent"], (int, float)):
        stats["percent"] = max(0, min(100, stats["percent"]))
    return stats


def _parse_nuclei_stats_line(line: str) -> dict | None:
    clean = _strip_ansi(line).strip()
    if not clean:
        return None
    if clean.startswith("{"):
        try:
            row = json.loads(clean)
        except Exception:
            return None
        if _looks_like_nuclei_finding(row):
            return None
        stats = _normalise_nuclei_stats(row, clean)
        return stats if stats and (len(stats.get("raw") or {}) > 0) else None

    pairs = {}
    for match in re.finditer(r"(?i)(templates?|hosts?|targets?|requests?|matched|matches|findings|errors?|failed|rps|progress|percent(?:age)?|duration|elapsed)\s*[:=]\s*([0-9][0-9.,%/a-zA-Z-]*)", clean):
        key = match.group(1).lower()
        value = match.group(2)
        if "/" in value and key in {"progress", "percent"}:
            done, total = value.split("/", 1)
            done_num = _coerce_nuclei_number(done)
            total_num = _coerce_nuclei_number(total)
            if isinstance(done_num, (int, float)) and isinstance(total_num, (int, float)) and total_num:
                pairs["percent"] = round((done_num / total_num) * 100, 1)
            pairs["progress"] = value
        else:
            pairs[key] = _coerce_nuclei_number(value)
    if pairs:
        return _normalise_nuclei_stats(pairs, clean)
    if "stats" in clean.lower() or "progress" in clean.lower() or "requests" in clean.lower():
        return {"raw": {}, "last_line": clean}
    return None


def _merge_nuclei_stats(existing: dict | None, update: dict | None, findings_count: int | None = None) -> dict:
    merged = dict(existing or {})
    if update:
        for key, value in update.items():
            if key == "raw":
                raw = dict(merged.get("raw") or {})
                raw.update(value or {})
                merged["raw"] = raw
            elif value not in (None, ""):
                merged[key] = value
    if findings_count is not None:
        matched = _coerce_nuclei_number(merged.get("matched"))
        if not isinstance(matched, (int, float)):
            matched = 0
        merged["matched"] = max(int(matched), int(findings_count))
    return merged


def _nuclei_progress_from_stats(state: dict) -> int | None:
    stats = state.get("stats") or {}
    percent = stats.get("percent")
    if isinstance(percent, (int, float)):
        return int(max(0, min(100, round(percent))))
    requests = stats.get("requests")
    hosts = stats.get("hosts") or state.get("total") or state.get("hosts_scanned")
    if isinstance(requests, (int, float)) and isinstance(hosts, (int, float)) and hosts > 0:
        # Request counts are not a perfect proxy for nuclei progress, but they prove
        # that the scanner is actively moving while nuclei has not emitted a percent.
        return int(max(5, min(95, round((requests / max(hosts, 1)) * 10))))
    return None


def _nuclei_public_state(scan_id: str) -> dict:
    with _nuclei_lock:
        state = dict(_nuclei_state.get(scan_id) or {})
        if not state:
            job = jobs.get_job(scan_id)
            return jobs.public_state(job) if job else {}
        state.pop("process", None)
        state.pop("hosts", None)
        state["logs"] = list(state.get("logs") or [])
        state["findings"] = list(state.get("findings") or [])
        state["findings_total"] = len(state["findings"])
        state["stats"] = _merge_nuclei_stats(state.get("stats"), None, len(state["findings"]))
        progress = _nuclei_progress_from_stats(state)
        if progress is not None:
            state["progress_percent"] = progress
        return state


def _nuclei_append_log(scan_id: str, line: str, stream: str = "stdout"):
    text = (line or "").strip()
    if not text:
        return
    entry = {"ts": db.now(), "stream": stream, "line": text[:1200]}
    with _nuclei_lock:
        state = _nuclei_state.get(scan_id)
        if not state:
            return
        logs = state.setdefault("logs", [])
        logs.append(entry)
        if len(logs) > NUCLEI_LOG_BUFFER:
            del logs[:-NUCLEI_LOG_BUFFER]
        payload = _nuclei_public_state_locked(scan_id)
    jobs.append_log(scan_id, text, stream=stream)
    broadcast("nuclei_log", {"id": scan_id, "entry": entry})
    broadcast("nuclei_update", payload)


def _nuclei_public_state_locked(scan_id: str) -> dict:
    state = dict(_nuclei_state.get(scan_id) or {})
    state.pop("process", None)
    state.pop("hosts", None)
    state["logs"] = list(state.get("logs") or [])
    state["findings"] = list(state.get("findings") or [])
    state["findings_total"] = len(state["findings"])
    state["stats"] = _merge_nuclei_stats(state.get("stats"), None, len(state["findings"]))
    progress = _nuclei_progress_from_stats(state)
    if progress is not None:
        state["progress_percent"] = progress
    return state


def _nuclei_set_state(scan_id: str, **updates) -> dict:
    with _nuclei_lock:
        state = _nuclei_state.get(scan_id)
        if not state:
            return {}
        state.update(updates)
        payload = _nuclei_public_state_locked(scan_id)
    persisted_updates = dict(updates)
    payload_copy = dict(payload)
    payload_copy.pop("id", None)
    payload_copy.pop("status", None)
    payload_copy.pop("progress", None)
    status = persisted_updates.pop("status", None)
    jobs.update_state(scan_id, **({"status": status} if status else {}), payload=payload_copy)
    broadcast("nuclei_update", payload)
    return payload


def _nuclei_active_statuses() -> set[str]:
    return {"queued", "preparing", "running", "paused", "stopping"}


def _nuclei_log_status(scan_id: str, message: str, **updates) -> dict:
    payload = _nuclei_set_state(scan_id, message=message, **updates)
    _nuclei_append_log(scan_id, message, stream="status")
    return payload


def _nuclei_scan_sort_key(state: dict) -> str:
    return str(state.get("started_at") or state.get("finished_at") or "")


def _nuclei_list_public(project_id: str | None = None, limit: int = 20, active_only: bool = False) -> list[dict]:
    with _nuclei_lock:
        states = list(_nuclei_state.values())
        persisted = [jobs.public_state(j) for j in jobs.list_jobs(job_type="nuclei_scan", project_id=project_id, active=active_only if active_only else None, limit=limit)]
        seen = {s.get("id") for s in states}
        states.extend([j for j in persisted if j.get("id") not in seen])
        if project_id:
            states = [s for s in states if s.get("project_id") == project_id]
        if active_only:
            active = _nuclei_active_statuses()
            states = [s for s in states if s.get("status") in active]
        states.sort(key=_nuclei_scan_sort_key, reverse=True)
        ids = [s.get("id") for s in states[:limit] if s.get("id")]
        return [_nuclei_public_state_locked(scan_id) for scan_id in ids]


def _run_nuclei_sync(pid: str, project_name: str, mode: str, hosts: list[str]) -> tuple[dict | None, str | None, int]:
    targets_file = ""
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(hosts) + "\n")
            targets_file = tf.name

        nuclei_bin = _resolve_nuclei_binary()
        if not nuclei_bin:
            return None, "nuclei binary not found in PATH, NUCLEI_BIN, /root/go/bin/nuclei, /usr/local/bin/nuclei, or /usr/bin/nuclei", 400
        templates_ok, templates_msg = _ensure_nuclei_templates(nuclei_bin)
        if not templates_ok:
            return None, templates_msg, 400

        templates_dir = _nuclei_templates_dir()
        cmd = _nuclei_command(nuclei_bin, targets_file, templates_dir)
        run = subprocess.run(cmd, text=True, capture_output=True, timeout=900)

        findings = []
        stats = {}
        parse_errors = 0
        for ln in (run.stdout or "").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            stats_update = _parse_nuclei_stats_line(ln)
            if stats_update:
                stats = _merge_nuclei_stats(stats, stats_update, len(findings))
                continue
            if not ln.startswith("{"):
                continue
            try:
                row = json.loads(ln)
                if _looks_like_nuclei_finding(row):
                    findings.append(_normalize_nuclei_finding(row))
            except Exception:
                parse_errors += 1

        stderr_tail = (run.stderr or "")[-4000:]
        stdout_tail = (run.stdout or "")[-4000:]
        if run.returncode != 0 and not findings:
            return None, f"Nuclei scan failed: {_nuclei_exit_error(run.returncode, stderr_tail, stdout_tail)}", 500

        try:
            db.asset_record_nuclei_findings(pid, findings, scan_id=f"sync:{int(time.time())}")
        except Exception as exc:
            log.warning("Unable to persist nuclei findings to asset inventory: %s", exc)
        return {
            "project_id": pid,
            "project_name": project_name,
            "scan_mode": mode,
            "hosts_scanned": len(hosts),
            "severities": ["medium", "high", "critical"],
            "command": "nuclei -l <hosts_file> -severity medium,high,critical -jsonl -stats -stats-json -duc -ud <templates_dir> -t <templates_dir> -rl <rate> -c <concurrency> -bs <bulk> -timeout <seconds>",
            "template_count": _nuclei_template_count(templates_dir),
            "resource_settings": _nuclei_resource_settings(),
            "findings": findings,
            "findings_total": len(findings),
            "stats": _merge_nuclei_stats(stats, None, len(findings)),
            "stderr": stderr_tail,
            "exit_code": run.returncode,
            "parse_errors": parse_errors,
            "templates_status": templates_msg,
        }, None, 200
    except subprocess.TimeoutExpired:
        return None, "Nuclei scan timed out after 900s", 504
    except FileNotFoundError:
        return None, "nuclei binary not found", 400
    except Exception as e:
        return None, f"Nuclei scan failed: {e}", 500
    finally:
        if targets_file:
            try:
                os.unlink(targets_file)
            except OSError:
                pass


def _nuclei_worker(scan_id: str):
    targets_file = ""
    started = time.time()
    try:
        _nuclei_log_status(scan_id, "Preparing nuclei target file and template directory", status="preparing")
        with _nuclei_lock:
            state = _nuclei_state.get(scan_id) or {}
            hosts = list(state.get("hosts") or [])
            pid = state.get("project_id")
            project_name = state.get("project_name")
            mode = state.get("scan_mode")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(hosts) + "\n")
            targets_file = tf.name

        nuclei_bin = _resolve_nuclei_binary()
        if not nuclei_bin:
            _nuclei_log_status(scan_id, "Nuclei binary was not found; install nuclei or set NUCLEI_BIN", status="error", error="nuclei binary not found in PATH, NUCLEI_BIN, /root/go/bin/nuclei, /usr/local/bin/nuclei, or /usr/bin/nuclei", finished_at=db.now())
            return
        templates_ok, templates_msg = _ensure_nuclei_templates(nuclei_bin)
        if not templates_ok:
            _nuclei_log_status(scan_id, f"Template preparation failed: {templates_msg}", status="error", error=templates_msg, templates_status=templates_msg, finished_at=db.now())
            return

        templates_dir = _nuclei_templates_dir()
        with _nuclei_lock:
            stopped_before_start = bool((_nuclei_state.get(scan_id) or {}).get("stop_requested"))
        if stopped_before_start:
            _nuclei_log_status(scan_id, "Nuclei scan stopped before process start", status="stopped", finished_at=db.now())
            return
        cmd = _nuclei_command(nuclei_bin, targets_file, templates_dir)
        _nuclei_append_log(scan_id, f"Binary: {nuclei_bin}", stream="status")
        template_count = _nuclei_template_count(templates_dir)
        resources = _nuclei_resource_settings()
        _nuclei_append_log(scan_id, f"Templates: {templates_dir} ({templates_msg}; {template_count} template files)", stream="status")
        _nuclei_append_log(scan_id, f"Resource limits: rate={resources['rate_limit']}/s concurrency={resources['concurrency']} bulk={resources['bulk_size']} timeout={resources['timeout']}s", stream="status")
        _nuclei_append_log(scan_id, f"Targets: {len(hosts)} host(s); mode={mode}; severities=medium,high,critical", stream="status")
        _nuclei_append_log(scan_id, "Command: nuclei -l <hosts_file> -severity medium,high,critical -jsonl -stats -stats-json -duc -ud <templates_dir> -t <templates_dir> -rl <rate> -c <concurrency> -bs <bulk> -timeout <seconds>", stream="status")
        _nuclei_set_state(scan_id, status="running", message="Nuclei process is starting", templates_status=templates_msg, template_count=template_count, resource_settings=resources, command=" ".join(cmd))
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )
        _nuclei_set_state(scan_id, process=process, process_id=process.pid, message=f"Nuclei process started (PID {process.pid})")
        _nuclei_append_log(scan_id, f"Process started with PID {process.pid}; streaming output below", stream="status")
        heartbeat_stop = threading.Event()

        def heartbeat():
            while not heartbeat_stop.wait(10):
                with _nuclei_lock:
                    state = _nuclei_state.get(scan_id) or {}
                    if state.get("status") not in {"running", "paused"}:
                        return
                    findings_count = len(state.get("findings") or [])
                    current_status = state.get("status") or "running"
                elapsed_hb = max(0, int(time.time() - started))
                _nuclei_append_log(scan_id, f"Still {current_status}: elapsed {elapsed_hb}s, findings {findings_count}, waiting for next nuclei event", stream="heartbeat")

        heartbeat_thread = threading.Thread(target=heartbeat, daemon=True, name=f"nuclei-heartbeat-{scan_id[:8]}")
        heartbeat_thread.start()
        parse_errors = 0
        assert process.stdout is not None
        for raw in process.stdout:
            line = raw.strip()
            if not line:
                continue
            parsed_finding = None
            stats_update = _parse_nuclei_stats_line(line)
            if stats_update:
                with _nuclei_lock:
                    state = _nuclei_state.get(scan_id)
                    if state:
                        findings_count = len(state.get("findings") or [])
                        state["stats"] = _merge_nuclei_stats(state.get("stats"), stats_update, findings_count)
                        state["last_stats_at"] = db.now()
                        state["message"] = "Nuclei stats updated"
                        progress = _nuclei_progress_from_stats(state)
                        if progress is not None:
                            state["progress_percent"] = progress
                        payload = _nuclei_public_state_locked(scan_id)
                    else:
                        payload = {}
                if payload:
                    broadcast("nuclei_stats", {"id": scan_id, "stats": payload.get("stats") or {}, "progress_percent": payload.get("progress_percent")})
                    broadcast("nuclei_update", payload)
            elif line.startswith("{"):
                try:
                    row = json.loads(line)
                    if _looks_like_nuclei_finding(row):
                        parsed_finding = _normalize_nuclei_finding(row)
                except Exception:
                    parse_errors += 1
            if parsed_finding:
                with _nuclei_lock:
                    state = _nuclei_state.get(scan_id)
                    if state:
                        state.setdefault("findings", []).append(parsed_finding)
                        state["stats"] = _merge_nuclei_stats(state.get("stats"), None, len(state.get("findings") or []))
                        state["parse_errors"] = parse_errors
                        state["last_finding_at"] = db.now()
                        payload = _nuclei_public_state_locked(scan_id)
                    else:
                        payload = {}
                broadcast("nuclei_finding", {"id": scan_id, "finding": parsed_finding})
                if payload:
                    broadcast("nuclei_update", payload)
            _nuclei_append_log(scan_id, line, stream="stats" if stats_update else "stdout")
        heartbeat_stop.set()
        exit_code = process.wait(timeout=10)
        elapsed = max(0, int(time.time() - started))
        with _nuclei_lock:
            state = _nuclei_state.get(scan_id) or {}
            stopped = bool(state.get("stop_requested"))
            findings = list(state.get("findings") or [])
        if pid:
            try:
                db.asset_record_nuclei_findings(pid, findings, scan_id=scan_id)
            except Exception as exc:
                log.warning("Unable to persist nuclei findings to asset inventory: %s", exc)
        if stopped:
            _nuclei_log_status(scan_id, "Nuclei scan stopped", status="stopped", exit_code=exit_code, finished_at=db.now(), elapsed_seconds=elapsed, progress_percent=100)
        elif exit_code != 0 and not findings:
            error_detail = _nuclei_exit_error(exit_code)
            _nuclei_log_status(scan_id, f"Nuclei exited with code {exit_code} and no findings. {error_detail}", status="error", exit_code=exit_code, finished_at=db.now(), elapsed_seconds=elapsed, error=error_detail, progress_percent=100)
        else:
            _nuclei_log_status(scan_id, f"Nuclei scan complete: {len(findings)} finding(s), exit code {exit_code}", status="done", exit_code=exit_code, finished_at=db.now(), elapsed_seconds=elapsed, progress_percent=100)
    except Exception as e:
        _nuclei_log_status(scan_id, f"Nuclei scan failed: {e}", status="error", error=f"Nuclei scan failed: {e}", finished_at=db.now())
    finally:
        if targets_file:
            try:
                os.unlink(targets_file)
            except OSError:
                pass
        with _nuclei_lock:
            state = _nuclei_state.get(scan_id)
            if state:
                state.pop("process", None)
            _nuclei_threads.pop(scan_id, None)


def _start_nuclei_scan(pid: str, project_name: str, mode: str, hosts: list[str]) -> dict:
    scan_id = db.uid()
    total = len(hosts)
    estimate_seconds = max(30, min(3600, total * 3))
    now = db.now()
    with _nuclei_lock:
        for existing in _nuclei_state.values():
            if existing.get("project_id") == pid and existing.get("status") in _nuclei_active_statuses():
                raise RuntimeError("A nuclei scan is already running for this project")
        jobs.create_job("nuclei_scan", id=scan_id, project_id=pid, status="queued", total=total, source=mode, payload={"project_name": project_name, "scan_mode": mode, "hosts_scanned": total, "severities": ["medium", "high", "critical"], "estimated_seconds": estimate_seconds, "estimated_completion_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + estimate_seconds)), "stats": {"hosts": total, "matched": 0, "errors": 0, "requests": 0}, "progress_percent": 0})
        _nuclei_state[scan_id] = {
            "id": scan_id,
            "project_id": pid,
            "project_name": project_name,
            "scan_mode": mode,
            "status": "queued",
            "message": "Nuclei scan queued",
            "hosts_scanned": total,
            "total": total,
            "severities": ["medium", "high", "critical"],
            "estimated_seconds": estimate_seconds,
            "estimated_completion_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + estimate_seconds)),
            "started_at": now,
            "findings": [],
            "findings_total": 0,
            "stats": {"hosts": total, "matched": 0, "errors": 0, "requests": 0},
            "progress_percent": 0,
            "parse_errors": 0,
            "logs": [],
            "hosts": hosts,
        }
    thread = threading.Thread(target=_nuclei_worker, args=(scan_id,), daemon=True, name=f"nuclei-scan-{scan_id[:8]}")
    with _nuclei_lock:
        _nuclei_threads[scan_id] = thread
    thread.start()
    payload = _nuclei_public_state(scan_id)
    broadcast("nuclei_update", payload)
    return payload


@api.post("/projects/<pid>/nuclei/scan")
def nuclei_scan_hosts(pid):
    p = db.project_get(pid)
    if not p:
        return err("Project not found", 404)

    mode = (request.args.get("mode", "latest_discoveries") or "latest_discoveries").strip().lower()
    if mode not in {"latest_discoveries", "all_subdomains"}:
        return err("Invalid mode. Use latest_discoveries or all_subdomains", 400)

    hosts = _resolve_nuclei_hosts(pid, mode)
    if not hosts:
        if mode == "all_subdomains":
            return err("No subdomains found for this project", 400)
        return err("No newly discovered hosts found for this project", 400)

    if (request.args.get("wait") or "").strip().lower() in {"1", "true", "yes"}:
        data, error_msg, code = _run_nuclei_sync(pid, p["name"], mode, hosts)
        if error_msg:
            return err(error_msg, code)
        return ok(data)

    try:
        payload = _start_nuclei_scan(pid, p["name"], mode, hosts)
    except RuntimeError as e:
        return err(str(e), 409)
    return ok({**payload, "message": f"Nuclei scan started for {len(hosts)} targets"})


@api.get("/nuclei/scans")
def nuclei_scans_list():
    project_id = (request.args.get("project_id") or "").strip() or None
    limit = _safe_int(request.args.get("limit", 20), 20, min_value=1, max_value=100)
    active_only = (request.args.get("active") or "").strip().lower() in {"1", "true", "yes"}
    return ok({"rows": _nuclei_list_public(project_id=project_id, limit=limit, active_only=active_only)})


@api.get("/nuclei/scans/<scan_id>")
def nuclei_scan_status(scan_id):
    state = _nuclei_public_state(scan_id)
    if not state:
        return err("Nuclei scan not found", 404)
    return ok(state)


@api.post("/nuclei/scans/<scan_id>/pause")
def pause_nuclei_scan(scan_id):
    with _nuclei_lock:
        state = _nuclei_state.get(scan_id)
        process = state.get("process") if state else None
        if not state:
            return err("Nuclei scan not found", 404)
        if state.get("status") != "running" or not process:
            return err("Nuclei scan is not running", 409)
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGSTOP)
    except Exception:
        process.send_signal(signal.SIGSTOP)
    jobs.request_pause(scan_id)
    return ok(_nuclei_set_state(scan_id, status="paused", message="Nuclei scan paused"))


@api.post("/nuclei/scans/<scan_id>/resume")
def resume_nuclei_scan(scan_id):
    with _nuclei_lock:
        state = _nuclei_state.get(scan_id)
        process = state.get("process") if state else None
        if not state:
            return err("Nuclei scan not found", 404)
        if state.get("status") != "paused" or not process:
            return err("Nuclei scan is not paused", 409)
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGCONT)
    except Exception:
        process.send_signal(signal.SIGCONT)
    jobs.request_resume(scan_id)
    return ok(_nuclei_set_state(scan_id, status="running", message="Nuclei scan resumed"))


@api.post("/nuclei/scans/<scan_id>/stop")
def stop_nuclei_scan(scan_id):
    with _nuclei_lock:
        state = _nuclei_state.get(scan_id)
        process = state.get("process") if state else None
        if not state:
            return err("Nuclei scan not found", 404)
        if state.get("status") not in {"queued", "preparing", "running", "paused"}:
            return err("Nuclei scan is not active", 409)
        state["stop_requested"] = True
    jobs.request_cancel(scan_id)
    if process:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except Exception:
            process.terminate()
    return ok(_nuclei_set_state(scan_id, status="stopping", message="Stopping nuclei scan"))


@api.post("/projects/<pid>/nuclei/scan-new-discoveries")
def nuclei_scan_new_discoveries(pid):
    return nuclei_scan_hosts(pid)
@api.post("/projects/<pid>/openssl")
def openssl_subjects(pid):
    p = db.project_get(pid)
    if not p:
        return err("Project not found", 404)

    # Keep this endpoint side-effect free: it reports certificate subjects for
    # already authorized inventory instead of launching hidden enumeration first.
    subfinder_job_id = None
    subfinder_error = ""
    hosts = _collect_openssl_hosts(pid)
    if not hosts:
        return err("No hosts found. Upload project hosts first.", 400)

    rows = [_run_openssl_subject(h) for h in hosts]
    db.openssl_results_upsert_batch(pid, rows, source="manual")
    return ok({
        "project_id": pid,
        "project_name": p["name"],
        "hosts_total": len(hosts),
        "subfinder_job_id": subfinder_job_id,
        "subfinder_error": subfinder_error,
        "command_template": "openssl s_client -connect HOSTNAME:443 </dev/null 2>/dev/null | grep subject",
        "rows": rows,
    })


@api.get("/projects/<pid>/openssl")
def openssl_subjects_list(pid):
    p = db.project_get(pid)
    if not p:
        return err("Project not found", 404)
    limit = _safe_int(request.args.get("limit", 2000), 2000, min_value=50, max_value=5000)
    search = (request.args.get("search", "") or "").strip()
    rows = db.openssl_results_list(pid, search=search, limit=limit)
    with _openssl_lock:
        status = dict(_openssl_status.get(pid) or {})
    if not status:
        status = jobs.public_state(jobs.get_job(f"openssl:{pid}")) or {"status": "idle"}
    return ok({
        "project_id": pid,
        "project_name": p["name"],
        "rows": rows,
        "rows_total": len(rows),
        "tracked_hosts": len(_collect_openssl_hosts(pid)),
        "worker": status,
    })


@api.post("/projects/<pid>/openssl/start")
def openssl_subjects_start(pid):
    p = db.project_get(pid)
    if not p:
        return err("Project not found", 404)
    started = _start_openssl_worker(pid, source="continuous")
    return ok({
        "project_id": pid,
        "project_name": p["name"],
        "started": started,
        "message": "OpenSSL continuous scan started" if started else "OpenSSL continuous scan already running",
    })


# ── Background SSE broadcaster for scan progress ───────────────────────────────

def _scan_broadcast_loop():
    """Pushes scan progress and stats via SSE every 3 seconds if anyone is scanning."""
    while True:
        try:
            active = list_active_scans()
            if active:
                for s in active:
                    broadcast("scan_update", s)
                # Also push updated stats
                broadcast("stats_update", db.stats_global())
                # Push alert count
                broadcast("alert_update", {"unseen_count": db.alerts_unseen_count()})
        except Exception:
            pass
        time.sleep(3)


threading.Thread(target=_scan_broadcast_loop, daemon=True, name="sse-broadcaster").start()
