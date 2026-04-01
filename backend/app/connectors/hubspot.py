"""HubSpot API connector."""

from __future__ import annotations

from .base import BaseConnector


class HubSpotConnector(BaseConnector):
    """Connector for HubSpot CRM API v3."""

    @property
    def name(self) -> str:
        return "hubspot"

    @property
    def base_url(self) -> str:
        return "https://api.hubapi.com"
