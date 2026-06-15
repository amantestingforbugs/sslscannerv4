from .base import BaseConnector, ConnectorResult


class CloudflareConnector(BaseConnector):
    type = "cloudflare"
    name = "Cloudflare"
    credential_env_vars = ("CLOUDFLARE_API_TOKEN",)

    def run(self) -> ConnectorResult:
        status = self.credential_status()
        if not status["ready"]:
            return ConnectorResult(status="error", errors=["Missing Cloudflare API token"], metadata=status)
        return ConnectorResult(metadata={**status, "message": "Cloudflare inventory collection stub; zones/DNS imports can be added here."})
