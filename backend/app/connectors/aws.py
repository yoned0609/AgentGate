"""AWS API Gateway connector."""

from __future__ import annotations

from .base import BaseConnector


class AWSConnector(BaseConnector):
    """Connector for AWS API Gateway (custom endpoint)."""

    @property
    def name(self) -> str:
        return "aws"

    @property
    def base_url(self) -> str:
        return "https://execute-api.us-east-1.amazonaws.com"
