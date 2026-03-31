"""Regression tests: Path normalization vulnerabilities.

Generated from vulnerability_report.json — GateBreaker Phase 1.
These tests MUST pass after patches are applied.

Vulnerabilities covered:
- VR-001: Double-slash prefix bypass (//calendars/...)
- VR-003: Percent-encoding bypass (/%63alendars/...)
- VR-004/005: Unicode slash lookalike bypass (U+2215, U+FF0F)
- VR-006/007: fnmatch slash boundary gap (/calendars/primary/sub/events)
"""

from __future__ import annotations

import asyncio

import pytest

from app.intent import IntentAnalyzer
from app.policy import PolicyEngine


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestPathNormalizationIntent:
    """Intent Analyzer must correctly classify paths despite obfuscation."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.analyzer = IntentAnalyzer()

    # VR-001: Double-slash prefix
    @pytest.mark.parametrize("path,expected_resource", [
        ("//calendars/primary/events", "calendar_event"),
        ("///calendars/primary/events", "calendar_event"),
        ("/calendars//primary//events", "calendar_event"),
        ("/calendars/primary//events//", "calendar_event"),
    ])
    def test_double_slash_normalized(self, path, expected_resource):
        result = _run(self.analyzer.analyze("GET", path, "google"))
        assert result.resource_type == expected_resource, \
            f"Path '{path}' should resolve to '{expected_resource}', got '{result.resource_type}'"

    # VR-003: Percent-encoding
    @pytest.mark.parametrize("path,expected_resource", [
        ("/%63alendars/primary/events", "calendar_event"),    # %63 = 'c'
        ("/calendars/primary%2Fevents", "calendar_event"),    # %2F = '/'
        ("/calendars/primary%2fevents", "calendar_event"),    # lowercase
        ("/cal%65ndars/primary/events", "calendar_event"),    # %65 = 'e'
    ])
    def test_percent_encoding_normalized(self, path, expected_resource):
        result = _run(self.analyzer.analyze("GET", path, "google"))
        assert result.resource_type == expected_resource, \
            f"Path '{path}' should resolve to '{expected_resource}', got '{result.resource_type}'"

    # VR-004/005: Unicode slash lookalikes
    @pytest.mark.parametrize("path", [
        "/\u2215calendars/primary/events",   # DIVISION SLASH
        "/calendars\uff0fprimary/events",    # FULLWIDTH SOLIDUS
    ])
    def test_unicode_slash_rejected_or_normalized(self, path):
        """Unicode slash lookalikes should either be normalized to '/' or
        cause the path to be classified as unknown (safe fail)."""
        result = _run(self.analyzer.analyze("GET", path, "google"))
        # After normalization, these should match correctly
        assert result.resource_type in ("calendar_event", "unknown")
        # If we normalize unicode slashes, it should match:
        if "\u2215" not in path and "\uff0f" not in path:
            assert result.resource_type == "calendar_event"

    # Dot-segment normalization
    @pytest.mark.parametrize("path,expected_resource", [
        ("/calendars/primary/./events", "calendar_event"),
        ("/calendars/./primary/events", "calendar_event"),
        ("/calendars/primary/events/./", "calendar_event"),
    ])
    def test_dot_segments_normalized(self, path, expected_resource):
        result = _run(self.analyzer.analyze("GET", path, "google"))
        assert result.resource_type == expected_resource


class TestPathNormalizationPolicy:
    """Policy Engine must match paths correctly despite obfuscation."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.engine = PolicyEngine(policy_dir="policies")

    # VR-006: fnmatch boundary — extra path SEGMENTS should NOT match allow rules
    # Note: /calendars/*/events/* is a valid rule for single events like /events/abc123
    # The vulnerability was /calendars/primary/sub/events matching /calendars/*/events
    @pytest.mark.parametrize("path", [
        "/calendars/primary/sub/events",           # extra segment between calendar and events
        "/calendars/primary/sub/extra/events",     # multiple extra segments
    ])
    def test_extra_segments_denied(self, path):
        """Paths with extra segments between wildcards must be denied."""
        decision = self.engine.evaluate("default", "GET", path)
        assert decision.effect == "deny", \
            f"Path '{path}' should be denied but got '{decision.effect}'"

    def test_traversal_normalizes_before_policy(self):
        """/evil/../events normalizes to /events, which correctly matches rules."""
        decision = self.engine.evaluate("default", "GET", "/calendars/primary/evil/../events")
        # After normalization: /calendars/primary/events -> allowed
        assert decision.effect == "allow"

    def test_single_event_path_still_allowed(self):
        """/calendars/*/events/* should still match single event reads."""
        decision = self.engine.evaluate("default", "GET", "/calendars/primary/events/abc123")
        assert decision.effect == "allow"

    # Normalized obfuscated paths should still match allow rules
    @pytest.mark.parametrize("path", [
        "/calendars//primary//events",
        "/calendars/primary/./events",
        "/calendars/primary/events/",
    ])
    def test_obfuscated_get_still_allowed(self, path):
        """GET to obfuscated-but-equivalent calendar paths should be allowed."""
        decision = self.engine.evaluate("default", "GET", path)
        assert decision.effect == "allow", \
            f"Normalized GET to '{path}' should be allowed but got '{decision.effect}'"


class TestPathNormalizationProxy:
    """Proxy path extraction must normalize before passing to intent/policy."""

    def test_extract_proxy_path_normalizes(self):
        from app.proxy import ReverseProxy
        # Double-slash prefix after provider stripping
        assert ReverseProxy._extract_proxy_path("/proxy/google//calendars/primary/events", "google") \
            == "/calendars/primary/events"

    def test_extract_proxy_path_dot_segments(self):
        from app.proxy import ReverseProxy
        assert ReverseProxy._extract_proxy_path("/proxy/google/calendars/./primary/events", "google") \
            == "/calendars/primary/events"
