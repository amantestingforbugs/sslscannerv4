from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ConnectorFinding:
    asset_type: str = "host"
    hostname: str = ""
    address: str = ""
    name: str = ""
    external_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_record(self) -> dict[str, Any]:
        return {
            "asset_type": self.asset_type,
            "hostname": self.hostname,
            "address": self.address,
            "name": self.name,
            "external_id": self.external_id,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class ConnectorResult:
    status: str = "done"
    findings: list[ConnectorFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == "done" and not self.errors


class BaseConnector:
    type = "base"
    name = "Base connector"
    credential_env_vars: tuple[str, ...] = ()

    def credential_status(self) -> dict[str, Any]:
        import os

        configured = [name for name in self.credential_env_vars if os.getenv(name)]
        missing = [name for name in self.credential_env_vars if not os.getenv(name)]
        return {"configured": configured, "missing": missing, "ready": not missing}

    def run(self) -> ConnectorResult:
        raise NotImplementedError
