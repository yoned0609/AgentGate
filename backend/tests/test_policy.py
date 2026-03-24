"""Tests for the policy engine."""

from app.policy import PolicyEngine


# ── Google Calendar (default / readwrite policies) ────────────────

def test_default_policy_allows_get_events():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("default", "GET", "/calendars/primary/events")
    assert decision.effect == "allow"


def test_default_policy_denies_post_events():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("default", "POST", "/calendars/primary/events")
    assert decision.effect == "deny"


def test_default_policy_denies_delete():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("default", "DELETE", "/calendars/primary/events/abc123")
    assert decision.effect == "deny"


def test_default_policy_allows_get_single_event():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("default", "GET", "/calendars/primary/events/abc123")
    assert decision.effect == "allow"


def test_default_policy_allows_freebusy():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("default", "POST", "/freeBusy")
    assert decision.effect == "allow"


def test_default_policy_denies_unknown_path():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("default", "GET", "/some/unknown/path")
    assert decision.effect == "deny"


def test_readwrite_policy_allows_post_events():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("readwrite", "POST", "/calendars/primary/events")
    assert decision.effect == "allow"


def test_readwrite_policy_allows_put_event():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("readwrite", "PUT", "/calendars/primary/events/abc123")
    assert decision.effect == "allow"


def test_readwrite_policy_denies_delete():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("readwrite", "DELETE", "/calendars/primary/events/abc123")
    assert decision.effect == "deny"


def test_unknown_policy_denies():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("nonexistent", "GET", "/calendars/primary/events")
    assert decision.effect == "deny"
    assert "not found" in (decision.reason or "")


def test_calendarlist_allowed():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("default", "GET", "/users/me/calendarList")
    assert decision.effect == "allow"


# ── Microsoft Graph policies ─────────────────────────────────────

def test_microsoft_readonly_allows_get_events():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("microsoft_readonly", "GET", "/me/calendar/events")
    assert decision.effect == "allow"


def test_microsoft_readonly_denies_post_events():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("microsoft_readonly", "POST", "/me/calendar/events")
    assert decision.effect == "deny"


def test_microsoft_readwrite_allows_post_events():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("microsoft_readwrite", "POST", "/me/calendar/events")
    assert decision.effect == "allow"


def test_microsoft_readwrite_denies_delete_events():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("microsoft_readwrite", "DELETE", "/me/calendar/events/abc")
    assert decision.effect == "deny"


def test_microsoft_readonly_allows_get_messages():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("microsoft_readonly", "GET", "/me/messages")
    assert decision.effect == "allow"


# ── Slack policies ───────────────────────────────────────────────

def test_slack_readonly_allows_conversations_list():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("slack_readonly", "POST", "/conversations.list")
    assert decision.effect == "allow"


def test_slack_readonly_denies_chat_post():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("slack_readonly", "POST", "/chat.postMessage")
    assert decision.effect == "deny"


def test_slack_readonly_denies_file_upload():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("slack_readonly", "POST", "/files.upload")
    assert decision.effect == "deny"


def test_slack_readonly_allows_users_list():
    engine = PolicyEngine(policy_dir="policies")
    decision = engine.evaluate("slack_readonly", "POST", "/users.list")
    assert decision.effect == "allow"
