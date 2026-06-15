"""Reusable asset risk scoring engine.

Scores are prioritization hints for authorized assets. The engine is purposely
pure-Python and database-agnostic so API, scheduler, and tests can reuse the same
factor weighting.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


SEVERITY_POINTS = {"info": 2, "low": 8, "medium": 18, "high": 30, "critical": 42}
CRITICALITY_POINTS = {"low": 2, "medium": 6, "high": 12, "critical": 18}
WEAK_TLS_VERSIONS = {"ssl", "sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"}
WEAK_CIPHER_MARKERS = ("rc4", "3des", "des", "null", "anon", "export", "md5")


@dataclass(frozen=True)
class Factor:
    name: str
    points: int
    evidence: str


def _truthy(value: Any) -> bool:
    return value in (True, 1, "1", "true", "True", "yes", "on")


def _text(value: Any) -> str:
    return str(value or "").strip()


def _severity(findings: list[dict]) -> tuple[int, str]:
    best = 0
    labels = []
    for finding in findings or []:
        sev = _text(finding.get("severity") or (finding.get("info") or {}).get("severity")).lower()
        points = SEVERITY_POINTS.get(sev, 0)
        if points:
            best = max(best, points)
            labels.append(sev)
    if not labels:
        return 0, "No Nuclei severity evidence"
    return best, f"Nuclei findings include {', '.join(sorted(set(labels)))} severity"


def score_asset(asset: dict, findings: list[dict] | None = None, observations: dict | None = None, context: dict | None = None) -> dict:
    """Return a normalized risk score with factor evidence for one asset.

    Inputs are dictionaries to keep the engine reusable across database rows,
    scanner results, API payloads, and tests. Output score is 0-100.
    """
    asset = asset or {}
    observations = observations or {}
    context = context or {}
    factors: list[Factor] = []

    hostname = _text(asset.get("hostname") or observations.get("hostname"))
    if _truthy(asset.get("internet_exposed")) or _truthy(observations.get("http_is_active")) or observations.get("http_status_code"):
        factors.append(Factor("internet_exposure", 18, "Internet-exposed host has active HTTP/TLS observations"))

    sev_points, sev_evidence = _severity(findings or [])
    if sev_points:
        factors.append(Factor("nuclei_severity", sev_points, sev_evidence))

    if _truthy(observations.get("is_mismatch")):
        factors.append(Factor("tls_mismatch", 20, "TLS certificate hostname mismatch detected"))
    if _truthy(observations.get("is_expired")):
        factors.append(Factor("tls_expired", 16, "TLS certificate is expired"))
    elif _truthy(observations.get("is_expiring")) or _truthy(observations.get("is_expiring_soon")):
        factors.append(Factor("tls_expiring", 8, "TLS certificate expires soon"))
    if observations.get("key_bits") and int(observations.get("key_bits") or 0) < 2048:
        factors.append(Factor("tls_weak_key", 12, f"TLS key size is {observations.get('key_bits')} bits"))
    tls_version = _text(observations.get("tls_version")).lower().replace(" ", "")
    cipher = _text(observations.get("cipher_suite")).lower()
    if tls_version in WEAK_TLS_VERSIONS or any(marker in cipher for marker in WEAK_CIPHER_MARKERS):
        factors.append(Factor("tls_weak_cipher", 10, "Weak TLS protocol or cipher signal observed"))

    status = observations.get("http_status_code")
    title = _text(observations.get("http_page_title"))
    if status in (401, 403):
        factors.append(Factor("http_protected_surface", 10, f"HTTP {status} indicates protected exposed surface"))
    elif isinstance(status, int) and status >= 500:
        factors.append(Factor("http_server_error", 8, f"HTTP {status} server error observed"))
    elif status in (200, 204, 301, 302, 307, 308):
        factors.append(Factor("http_reachable", 6, f"HTTP {status} reachable surface observed"))
    if title:
        sensitive = [w for w in ("admin", "login", "swagger", "openapi", "graphql", "dashboard") if w in title.lower()]
        if sensitive:
            factors.append(Factor("http_title_signal", 8, f"Page title suggests {', '.join(sensitive)} surface"))

    if _truthy(asset.get("is_latest_discovery")) or _truthy(observations.get("is_latest_discovery")):
        factors.append(Factor("fresh_discovery", 10, "Fresh Subfinder discovery needs ownership validation"))

    criticality = _text(asset.get("criticality") or context.get("criticality")).lower()
    owner = _text(asset.get("owner") or context.get("owner"))
    if criticality in CRITICALITY_POINTS:
        factors.append(Factor("asset_criticality", CRITICALITY_POINTS[criticality], f"Asset criticality is {criticality}"))
    if owner:
        factors.append(Factor("asset_owner", 3, f"Owner tag present: {owner}"))

    score = max(0, min(100, sum(f.points for f in factors)))
    severity = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"
    return {
        "hostname": hostname,
        "score": score,
        "severity": severity,
        "factors": [f.__dict__ for f in factors],
        "evidence": [f.evidence for f in factors][:12] or ["No elevated risk factors observed"],
    }
