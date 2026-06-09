"""Target safety policy for all scanner entry points.

The scanner can make outbound TLS and HTTP requests. Centralizing target
validation keeps bug-bounty/company deployments from accidentally scanning
internal infrastructure or assets outside the authorized scope.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from functools import lru_cache
from urllib.parse import urlparse

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:  # pragma: no cover - optional dependency is in requirements
    HAS_TLDEXTRACT = False

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]+(?:\.[a-z0-9-]+)+$", re.IGNORECASE)
_LOCAL_HOSTNAMES = {"localhost", "ip6-localhost", "ip6-loopback"}


def _split_csv_env(name: str) -> list[str]:
    return [item.strip().lower().lstrip(".") for item in os.getenv(name, "").split(",") if item.strip()]


def allowed_scope_domains() -> list[str]:
    """Return globally allowed root/suffix domains from SCAN_ALLOWED_DOMAINS."""
    return _split_csv_env("SCAN_ALLOWED_DOMAINS")


def allow_private_targets() -> bool:
    """Whether private, loopback, link-local and reserved targets may be scanned."""
    return os.getenv("ALLOW_PRIVATE_SCAN_TARGETS", "").strip().lower() in {"1", "true", "yes", "on"}


def registered_domain(hostname: str) -> str:
    host = (hostname or "").strip().lower().strip(".")
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if HAS_TLDEXTRACT:
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def is_ip_disallowed(host: str) -> bool:
    try:
        ip = ipaddress.ip_address((host or "").strip().strip("[]"))
    except ValueError:
        return False
    return any([
        ip.is_private,
        ip.is_loopback,
        ip.is_link_local,
        ip.is_multicast,
        ip.is_reserved,
        ip.is_unspecified,
    ])


def normalize_hostname(raw: str, *, allow_ip: bool = False) -> str:
    """Normalize a user-supplied host/URL into a lowercase hostname/IP."""
    value = (raw or "").strip().lower()
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = (parsed.hostname or value.split("/", 1)[0].split(":", 1)[0]).strip().strip(".[]")
    if not host or host in _LOCAL_HOSTNAMES:
        return ""
    try:
        ipaddress.ip_address(host)
        return host if allow_ip else ""
    except ValueError:
        return host if _HOSTNAME_RE.match(host) else ""


def is_in_allowed_scope(hostname: str, allowed_domains: list[str] | None = None) -> bool:
    allowed = allowed_scope_domains() if allowed_domains is None else [d.lower().lstrip(".") for d in allowed_domains if d]
    if not allowed:
        return True
    host = (hostname or "").strip().lower().strip(".")
    root = registered_domain(host)
    return any(host == domain or host.endswith(f".{domain}") or root == domain for domain in allowed)


@lru_cache(maxsize=4096)
def resolves_to_disallowed_ip(hostname: str) -> bool:
    """Resolve host and reject it if any answer is unsafe for public scanning."""
    host = (hostname or "").strip().lower().strip(".")
    if not host or allow_private_targets():
        return False
    if is_ip_disallowed(host):
        return True
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    for answer in answers:
        sockaddr = answer[4]
        if sockaddr and is_ip_disallowed(sockaddr[0]):
            return True
    return False


def is_target_allowed(hostname: str, *, allowed_domains: list[str] | None = None, check_dns: bool = False) -> bool:
    host = (hostname or "").strip().lower().strip(".")
    if not host:
        return False
    if not allow_private_targets() and (host in _LOCAL_HOSTNAMES or is_ip_disallowed(host)):
        return False
    if not is_in_allowed_scope(host, allowed_domains):
        return False
    if check_dns and resolves_to_disallowed_ip(host):
        return False
    return True


def filter_allowed_hosts(hosts: list[str], *, allow_ip: bool = False, check_dns: bool = False) -> tuple[list[str], list[str]]:
    """Normalize, de-duplicate, and split hosts into allowed and rejected lists."""
    allowed: list[str] = []
    rejected: list[str] = []
    seen: set[str] = set()
    for raw in hosts:
        host = normalize_hostname(raw, allow_ip=allow_ip)
        if not host or not is_target_allowed(host, check_dns=check_dns):
            rejected.append(str(raw))
            continue
        if host not in seen:
            seen.add(host)
            allowed.append(host)
    return allowed, rejected
