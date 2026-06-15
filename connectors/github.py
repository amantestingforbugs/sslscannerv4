from .base import BaseConnector, ConnectorResult


class GitHubConnector(BaseConnector):
    type = "github"
    name = "GitHub"
    credential_env_vars = ("GITHUB_TOKEN",)

    def run(self) -> ConnectorResult:
        status = self.credential_status()
        if not status["ready"]:
            return ConnectorResult(status="error", errors=["Missing GitHub token"], metadata=status)
        return ConnectorResult(metadata={**status, "message": "GitHub inventory collection stub; org/repo environment imports can be added here."})
