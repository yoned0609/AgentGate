"""Provider connectors — maps provider names to connector instances."""

from __future__ import annotations

from .base import BaseConnector
from .google_calendar import GoogleCalendarConnector
from .microsoft_graph import MicrosoftGraphConnector
from .slack import SlackConnector
from .github import GitHubConnector
from .jira import JiraConnector
from .notion import NotionConnector
from .linear import LinearConnector
from .hubspot import HubSpotConnector
from .salesforce import SalesforceConnector
from .aws import AWSConnector

CONNECTOR_REGISTRY: dict[str, type[BaseConnector]] = {
    "google": GoogleCalendarConnector,
    "microsoft": MicrosoftGraphConnector,
    "slack": SlackConnector,
    "github": GitHubConnector,
    "jira": JiraConnector,
    "notion": NotionConnector,
    "linear": LinearConnector,
    "hubspot": HubSpotConnector,
    "salesforce": SalesforceConnector,
    "aws": AWSConnector,
}


def get_connector(provider: str) -> BaseConnector | None:
    """Return a connector instance for the given provider name."""
    cls = CONNECTOR_REGISTRY.get(provider)
    return cls() if cls else None


def available_providers() -> list[str]:
    """Return list of supported provider names."""
    return list(CONNECTOR_REGISTRY.keys())
