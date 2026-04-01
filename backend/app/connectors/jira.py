"""Jira Cloud API connector."""

from __future__ import annotations

from fastapi import Request

from .base import BaseConnector


class JiraConnector(BaseConnector):
    """Connector for Jira Cloud REST API v3."""

    @property
    def name(self) -> str:
        return "jira"

    @property
    def base_url(self) -> str:
        return "https://your-domain.atlassian.net/rest/api/3"

    def build_forward_headers(self, request: Request) -> dict[str, str]:
        headers = super().build_forward_headers(request)
        headers["Accept"] = "application/json"
        return headers
