"""Google Calendar API connector."""

from __future__ import annotations

from .base import BaseConnector


class GoogleCalendarConnector(BaseConnector):
    """Connector for Google Calendar API v3."""

    @property
    def name(self) -> str:
        return "google"

    @property
    def base_url(self) -> str:
        return "https://www.googleapis.com/calendar/v3"
