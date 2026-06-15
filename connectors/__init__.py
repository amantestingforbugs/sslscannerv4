"""Connector framework for importing external asset inventory."""

from .base import BaseConnector, ConnectorFinding, ConnectorResult
from .aws import AWSConnector
from .cloudflare import CloudflareConnector
from .github import GitHubConnector

CONNECTOR_TYPES = {
    "aws": AWSConnector,
    "cloudflare": CloudflareConnector,
    "github": GitHubConnector,
}


def get_connector(connector_type: str) -> BaseConnector:
    try:
        return CONNECTOR_TYPES[connector_type]()
    except KeyError as exc:
        raise ValueError(f"Unsupported connector type: {connector_type}") from exc
