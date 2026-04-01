"""Salesforce API connector."""

from __future__ import annotations

from .base import BaseConnector


class SalesforceConnector(BaseConnector):
    """Connector for Salesforce REST API."""

    @property
    def name(self) -> str:
        return "salesforce"

    @property
    def base_url(self) -> str:
        return "https://your-instance.salesforce.com/services/data/v59.0"
