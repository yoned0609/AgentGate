"""GitHub API connector."""

from __future__ import annotations

from .base import BaseConnector


class GitHubConnector(BaseConnector):
    """Connector for GitHub REST API v3."""

    @property
    def name(self) -> str:
        return "github"

    @property
    def base_url(self) -> str:
        return "https://api.github.com"
