"""Tests for provider connectors."""

from app.connectors import available_providers, get_connector


def test_available_providers():
    providers = available_providers()
    assert "google" in providers
    assert "microsoft" in providers
    assert "slack" in providers


def test_get_google_connector():
    c = get_connector("google")
    assert c is not None
    assert c.name == "google"
    assert "googleapis.com" in c.base_url


def test_get_microsoft_connector():
    c = get_connector("microsoft")
    assert c is not None
    assert c.name == "microsoft"
    assert "graph.microsoft.com" in c.base_url


def test_get_slack_connector():
    c = get_connector("slack")
    assert c is not None
    assert c.name == "slack"
    assert "slack.com/api" in c.base_url


def test_unknown_provider_returns_none():
    assert get_connector("unknown") is None


def test_google_build_target_url():
    c = get_connector("google")
    url = c.build_target_url("/calendars/primary/events", "maxResults=10")
    assert url == "https://www.googleapis.com/calendar/v3/calendars/primary/events?maxResults=10"


def test_microsoft_build_target_url():
    c = get_connector("microsoft")
    url = c.build_target_url("/me/calendar/events", "")
    assert url == "https://graph.microsoft.com/v1.0/me/calendar/events"


def test_slack_build_target_url():
    c = get_connector("slack")
    url = c.build_target_url("/conversations.list", "")
    assert url == "https://slack.com/api/conversations.list"
