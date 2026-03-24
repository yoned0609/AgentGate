"""Tests for the policy engine."""

from app.policy import PolicyEngine


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
