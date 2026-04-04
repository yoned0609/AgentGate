"""Mock response generator for TEST_MODE.

When TEST_MODE=true, this module provides realistic Google Calendar API v3
responses so testers can verify proxy behavior without real API credentials.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = None  # allow tests to override


def _utcnow() -> datetime:
    return _NOW or datetime.now(timezone.utc)


def _ts(dt: datetime) -> str:
    """Format datetime as RFC 3339 string."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ---------------------------------------------------------------------------
# Mock data builders
# ---------------------------------------------------------------------------


def _mock_event(event_id: str, summary: str, offset_hours: int) -> dict:
    start = _utcnow() + timedelta(hours=offset_hours)
    end = start + timedelta(hours=1)
    return {
        "kind": "calendar#event",
        "etag": f'"mock-etag-{event_id}"',
        "id": event_id,
        "status": "confirmed",
        "htmlLink": f"https://www.google.com/calendar/event?eid={event_id}",
        "created": _ts(_utcnow() - timedelta(days=7)),
        "updated": _ts(_utcnow()),
        "summary": summary,
        "creator": {"email": "testuser@example.com", "self": True},
        "organizer": {"email": "testuser@example.com", "self": True},
        "start": {"dateTime": _ts(start), "timeZone": "UTC"},
        "end": {"dateTime": _ts(end), "timeZone": "UTC"},
        "iCalUID": f"{event_id}@google.com",
        "sequence": 0,
        "reminders": {"useDefault": True},
    }


def _events_list() -> dict:
    now = _utcnow()
    return {
        "kind": "calendar#events",
        "etag": '"mock-events-etag"',
        "summary": "testuser@example.com",
        "updated": _ts(now),
        "timeZone": "UTC",
        "accessRole": "owner",
        "nextSyncToken": "mock-sync-token-abc123",
        "items": [
            _mock_event("mock-evt-001", "Team Standup", 1),
            _mock_event("mock-evt-002", "Design Review", 3),
            _mock_event("mock-evt-003", "Lunch Break", 5),
        ],
    }


def _single_event(event_id: str) -> dict:
    return _mock_event(event_id, "Mock Event", 2)


def _free_busy() -> dict:
    now = _utcnow()
    busy_start = now + timedelta(hours=1)
    busy_end = busy_start + timedelta(hours=1)
    return {
        "kind": "calendar#freeBusy",
        "timeMin": _ts(now),
        "timeMax": _ts(now + timedelta(days=1)),
        "calendars": {
            "testuser@example.com": {
                "busy": [
                    {"start": _ts(busy_start), "end": _ts(busy_end)},
                ],
            },
        },
    }


def _calendar_list() -> dict:
    return {
        "kind": "calendar#calendarList",
        "etag": '"mock-calendarlist-etag"',
        "nextSyncToken": "mock-calsync-token-xyz",
        "items": [
            {
                "kind": "calendar#calendarListEntry",
                "etag": '"mock-cal-etag-1"',
                "id": "testuser@example.com",
                "summary": "testuser@example.com",
                "timeZone": "UTC",
                "colorId": "1",
                "backgroundColor": "#ac725e",
                "foregroundColor": "#1d1d1d",
                "selected": True,
                "accessRole": "owner",
                "defaultReminders": [{"method": "popup", "minutes": 10}],
                "primary": True,
            },
            {
                "kind": "calendar#calendarListEntry",
                "etag": '"mock-cal-etag-2"',
                "id": "holidays@group.v1.calendar.google.com",
                "summary": "Holidays in Japan",
                "timeZone": "UTC",
                "colorId": "8",
                "backgroundColor": "#16a765",
                "foregroundColor": "#000000",
                "selected": True,
                "accessRole": "reader",
                "defaultReminders": [],
            },
        ],
    }


# ---------------------------------------------------------------------------
# Route patterns
# ---------------------------------------------------------------------------

_EVENTS_LIST_RE = re.compile(r"^/calendars/[^/]+/events/?$")
_EVENTS_SINGLE_RE = re.compile(r"^/calendars/[^/]+/events/([^/]+)$")
_FREE_BUSY_RE = re.compile(r"^/freeBusy/?$")
_CALENDAR_LIST_RE = re.compile(r"^/users/me/calendarList/?$")


def build_mock_response(method: str, path: str) -> tuple[int, dict, bytes]:
    """Return (status_code, headers, body_bytes) for a mock response.

    The caller should wrap this into a ``fastapi.Response``.
    """
    headers = {"X-AgentGate-TestMode": "true"}

    # POST /freeBusy
    if method == "POST" and _FREE_BUSY_RE.match(path):
        body = _free_busy()
        return 200, headers, json.dumps(body).encode()

    # GET /calendars/{id}/events
    if method == "GET" and _EVENTS_LIST_RE.match(path):
        body = _events_list()
        return 200, headers, json.dumps(body).encode()

    # GET /calendars/{id}/events/{eventId}
    m = _EVENTS_SINGLE_RE.match(path)
    if method == "GET" and m:
        event_id = m.group(1)
        body = _single_event(event_id)
        return 200, headers, json.dumps(body).encode()

    # GET /users/me/calendarList
    if method == "GET" and _CALENDAR_LIST_RE.match(path):
        body = _calendar_list()
        return 200, headers, json.dumps(body).encode()

    # Fallback for any other GET
    if method == "GET":
        body = {"mock": True, "path": path, "message": "Test mode active"}
        return 200, headers, json.dumps(body).encode()

    # Fallback for non-GET (unlikely to reach here since policy denies most writes)
    body = {"mock": True, "path": path, "method": method, "message": "Test mode active"}
    return 200, headers, json.dumps(body).encode()
