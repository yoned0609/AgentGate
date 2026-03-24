"""Microsoft Graph API connector."""

from __future__ import annotations

from .base import BaseConnector


class MicrosoftGraphConnector(BaseConnector):
    """Connector for Microsoft Graph API (Calendar, Mail, etc.)."""

    @property
    def name(self) -> str:
        return "microsoft"

    @property
    def base_url(self) -> str:
        return "https://graph.microsoft.com/v1.0"
