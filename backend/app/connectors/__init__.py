"""Provider connectors — maps provider names to connector instances."""

from __future__ import annotations

from .base import BaseConnector
from .google_calendar import GoogleCalendarConnector
from .microsoft_graph import MicrosoftGraphConnector
from .slack import SlackConnector

CONNECTOR_REGISTRY: dict[str, type[BaseConnector]] = {
    "google": GoogleCalendarConnector,
    "microsoft": MicrosoftGraphConnector,
    "slack": SlackConnector,
}


def get_connector(provider: str) -> BaseConnector | None:
    """Return a connector instance for the given provider name."""
    cls = CONNECTOR_REGISTRY.get(provider)
    return cls() if cls else None


def available_providers() -> list[str]:
    """Return list of supported provider names."""
    return list(CONNECTOR_REGISTRY.keys())
