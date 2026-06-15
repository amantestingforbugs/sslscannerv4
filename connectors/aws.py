from .base import BaseConnector, ConnectorResult


class AWSConnector(BaseConnector):
    type = "aws"
    name = "AWS"
    credential_env_vars = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")

    def run(self) -> ConnectorResult:
        status = self.credential_status()
        if not status["ready"]:
            return ConnectorResult(status="error", errors=["Missing AWS environment credentials"], metadata=status)
        return ConnectorResult(metadata={**status, "message": "AWS inventory collection stub; discovery adapters can be added without changing api/routes.py."})
