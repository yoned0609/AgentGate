"""Tests for intent analyzer."""

import asyncio

from app.intent import IntentAnalyzer


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_get_is_read():
    analyzer = IntentAnalyzer()
    result = _run(analyzer.analyze("GET", "/calendars/primary/events", "google"))
    assert result.intent_type == "read"
    assert result.resource_type == "calendar_event"
    assert result.confidence >= 0.9


def test_post_is_create():
    analyzer = IntentAnalyzer()
    result = _run(analyzer.analyze("POST", "/calendars/primary/events", "google"))
    assert result.intent_type == "create"
    assert result.resource_type == "calendar_event"


def test_delete_is_delete():
    analyzer = IntentAnalyzer()
    result = _run(analyzer.analyze("DELETE", "/calendars/primary/events/abc", "google"))
    assert result.intent_type == "delete"


def test_put_is_update():
    analyzer = IntentAnalyzer()
    result = _run(analyzer.analyze("PUT", "/calendars/primary/events/abc", "google"))
    assert result.intent_type == "update"


def test_microsoft_calendar_read():
    analyzer = IntentAnalyzer()
    result = _run(analyzer.analyze("GET", "/me/calendar/events", "microsoft"))
    assert result.intent_type == "read"
    assert result.resource_type == "calendar_event"


def test_microsoft_mail_read():
    analyzer = IntentAnalyzer()
    result = _run(analyzer.analyze("GET", "/me/messages", "microsoft"))
    assert result.intent_type == "read"
    assert result.resource_type == "mail_message"


def test_slack_read_method_via_post():
    """Slack API uses POST for reads — intent should still be 'read'."""
    analyzer = IntentAnalyzer()
    result = _run(analyzer.analyze("POST", "/conversations.list", "slack"))
    assert result.intent_type == "read"
    assert result.resource_type == "channel"


def test_slack_write_method():
    """Slack chat.postMessage is a write despite being POST."""
    analyzer = IntentAnalyzer()
    result = _run(analyzer.analyze("POST", "/chat.postMessage", "slack"))
    assert result.intent_type == "create"
    assert result.resource_type == "message"


def test_unknown_path():
    analyzer = IntentAnalyzer()
    result = _run(analyzer.analyze("GET", "/some/unknown/path", "google"))
    assert result.intent_type == "read"
    assert result.resource_type == "unknown"
    assert result.confidence < 0.9


def test_freebusy_query():
    analyzer = IntentAnalyzer()
    result = _run(analyzer.analyze("POST", "/freeBusy", "google"))
    assert result.resource_type == "availability"
