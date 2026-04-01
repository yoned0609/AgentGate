"""Linear API connector."""

from __future__ import annotations

from .base import BaseConnector


class LinearConnector(BaseConnector):
    """Connector for Linear GraphQL API."""

    @property
    def name(self) -> str:
        return "linear"

    @property
    def base_url(self) -> str:
        return "https://api.linear.app"
