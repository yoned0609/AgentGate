"""Slack Web API connector."""

from __future__ import annotations

from fastapi import Request

from .base import BaseConnector


class SlackConnector(BaseConnector):
    """Connector for Slack Web API.

    Slack uses token-based auth via Authorization header (Bearer token)
    and all methods are POST with application/json or form-encoded bodies.
    """

    @property
    def name(self) -> str:
        return "slack"

    @property
    def base_url(self) -> str:
        return "https://slack.com/api"

    def build_forward_headers(self, request: Request) -> dict[str, str]:
        headers = super().build_forward_headers(request)
        # Slack expects application/json for most methods
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/json; charset=utf-8"
        return headers
