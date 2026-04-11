"""Tests for Semantic Poka-yoke streaming validation + risk classification."""

import json
import pytest
from app.semantic_rules import (
    CheckType,
    PatternCheck,
    RuleMode,
    SemanticRule,
    StreamingValidator,
    StreamingCheckResult,
    Violation,
    classify_risk,
)


# ── Helpers ────────────────────────────────────────────────────────────


def _rule(
    name: str = "test_rule",
    checks: list[PatternCheck] | None = None,
    mode: RuleMode = RuleMode.ENFORCE,
    severity: str = "high",
) -> SemanticRule:
    return SemanticRule(
        name=name,
        description=f"Test: {name}",
        checks=checks or [],
        mode=mode,
        severity=severity,
        violation_message=f"Violation: {name}",
    )


def _check_regex(pattern: str) -> PatternCheck:
    return PatternCheck(check_type=CheckType.REGEX, pattern=pattern)


def _check_keyword(keywords: str) -> PatternCheck:
    return PatternCheck(check_type=CheckType.KEYWORD, pattern=keywords)


def _check_numeric(field_path: str, max_value: float) -> PatternCheck:
    return PatternCheck(
        check_type=CheckType.NUMERIC_RANGE,
        field_path=field_path,
        max_value=max_value,
    )


# ── StreamingValidator: basic chunk validation ─────────────────────────


class TestStreamingBasic:
    def test_clean_chunks_pass(self):
        rule = _rule(checks=[_check_keyword("SECRET")])
        sv = StreamingValidator([rule])

        r1 = sv.feed(b'{"data": "hello"}')
        r2 = sv.feed(b'{"more": "world"}')

        assert not r1.should_terminate
        assert not r2.should_terminate
        assert not sv.terminated

    def test_violation_in_single_chunk(self):
        rule = _rule(checks=[_check_keyword("SECRET")])
        sv = StreamingValidator([rule])

        result = sv.feed(b'{"password": "SECRET"}')
        assert result.should_terminate
        assert sv.terminated
        assert len(result.violations) == 1

    def test_regex_violation_in_chunk(self):
        rule = _rule(checks=[_check_regex(r"\b\d{3}-\d{2}-\d{4}\b")])
        sv = StreamingValidator([rule])

        result = sv.feed(b'{"ssn": "123-45-6789"}')
        assert result.should_terminate

    def test_audit_mode_does_not_terminate(self):
        rule = _rule(mode=RuleMode.AUDIT, checks=[_check_keyword("flagged")])
        sv = StreamingValidator([rule])

        result = sv.feed(b'{"data": "flagged content"}')
        assert not result.should_terminate
        assert len(result.violations) == 1
        assert not sv.terminated


# ── Sliding window: cross-boundary detection ──────────────────────────


class TestSlidingWindow:
    def test_pattern_split_across_chunks(self):
        """Credit card number split across two chunks must still be detected."""
        rule = _rule(checks=[_check_regex(r"\b4111111111111111\b")])
        sv = StreamingValidator([rule], overlap=32)

        # Split the card number across chunk boundary
        r1 = sv.feed(b'{"card": "41111111')
        assert not r1.should_terminate

        # Second chunk completes the number — overlap window catches it
        r2 = sv.feed(b'11111111"}')
        assert r2.should_terminate

    def test_keyword_split_across_chunks(self):
        """Keyword 'CONFIDENTIAL' split across boundary."""
        rule = _rule(checks=[_check_keyword("CONFIDENTIAL")])
        sv = StreamingValidator([rule], overlap=32)

        r1 = sv.feed(b'{"note": "This is CONFID')
        assert not r1.should_terminate

        r2 = sv.feed(b'ENTIAL data"}')
        assert r2.should_terminate

    def test_overlap_configurable(self):
        """With overlap=0, cross-boundary patterns are NOT detected."""
        rule = _rule(checks=[_check_keyword("CONFIDENTIAL")])
        sv = StreamingValidator([rule], overlap=0)

        r1 = sv.feed(b'CONFID')
        r2 = sv.feed(b'ENTIAL')
        # Neither chunk alone contains full keyword, and no overlap
        assert not r1.should_terminate
        assert not r2.should_terminate


# ── Finalize: deferred checks ─────────────────────────────────────────


class TestFinalize:
    def test_numeric_check_deferred_to_finalize(self):
        """Numeric range checks only run in finalize(), not per-chunk."""
        rule = _rule(checks=[_check_numeric("amount", max_value=100)])
        sv = StreamingValidator([rule])

        # Feed the full JSON as chunks
        r1 = sv.feed(b'{"amount": 999}')
        assert not r1.should_terminate  # numeric_range is deferred

        final = sv.finalize()
        assert not final.passed
        assert len(final.violations) == 1
        assert final.violations[0].check_type == "numeric_range"

    def test_finalize_clean(self):
        rule = _rule(checks=[_check_numeric("amount", max_value=1000)])
        sv = StreamingValidator([rule])

        sv.feed(b'{"amount": 50}')
        final = sv.finalize()
        assert final.passed

    def test_finalize_combines_chunk_and_deferred_violations(self):
        """Violations from chunk scanning + finalize are merged."""
        rules = [
            _rule(name="kw", checks=[_check_keyword("SECRET")]),
            _rule(name="num", checks=[_check_numeric("amount", max_value=100)]),
        ]
        sv = StreamingValidator(rules)

        sv.feed(b'{"secret": "SECRET", "amount": 999}')
        assert sv.terminated  # keyword triggered termination

        final = sv.finalize()
        assert not final.passed
        # Should have keyword violation (from chunk) + numeric (from finalize)
        assert len(final.violations) == 2
        types = {v.check_type for v in final.violations}
        assert "keyword" in types
        assert "numeric_range" in types


# ── Post-termination behavior ──────────────────────────────────────────


class TestPostTermination:
    def test_feed_after_termination_returns_terminate(self):
        rule = _rule(checks=[_check_keyword("BAD")])
        sv = StreamingValidator([rule])

        sv.feed(b"BAD data")
        assert sv.terminated

        # Further feeds should also return should_terminate
        result = sv.feed(b"more data")
        assert result.should_terminate

    def test_stats_tracking(self):
        rule = _rule(checks=[_check_keyword("BAD")])
        sv = StreamingValidator([rule])

        sv.feed(b"chunk 1")
        sv.feed(b"chunk 2")
        sv.feed(b"BAD chunk 3")

        stats = sv.stats
        assert stats["chunks_checked"] == 3
        assert stats["total_bytes"] == len(b"chunk 1") + len(b"chunk 2") + len(b"BAD chunk 3")
        assert stats["violations_found"] == 1
        assert stats["terminated"] is True


# ── Rule filtering in StreamingValidator ───────────────────────────────


class TestStreamingFiltering:
    def test_provider_filter(self):
        rule = SemanticRule(
            name="sf_only",
            description="Salesforce only",
            providers=["salesforce"],
            checks=[_check_keyword("SECRET")],
            mode=RuleMode.ENFORCE,
        )
        # Google provider — rule should not apply
        sv = StreamingValidator([rule], provider="google")
        result = sv.feed(b"SECRET data")
        assert not result.should_terminate

        # Salesforce — rule applies
        sv2 = StreamingValidator([rule], provider="salesforce")
        result2 = sv2.feed(b"SECRET data")
        assert result2.should_terminate

    def test_method_filter(self):
        rule = SemanticRule(
            name="get_only",
            description="GET only",
            methods=["GET"],
            checks=[_check_keyword("SECRET")],
            mode=RuleMode.ENFORCE,
        )
        sv_post = StreamingValidator([rule], method="POST")
        result = sv_post.feed(b"SECRET data")
        assert not result.should_terminate

        sv_get = StreamingValidator([rule], method="GET")
        result2 = sv_get.feed(b"SECRET data")
        assert result2.should_terminate


# ── Risk classification ────────────────────────────────────────────────


class TestRiskClassification:
    def test_write_methods_always_buffer(self):
        assert classify_risk("google", "/calendars/events", "POST") == "buffer"
        assert classify_risk("google", "/calendars/events", "PUT") == "buffer"
        assert classify_risk("google", "/calendars/events", "PATCH") == "buffer"
        assert classify_risk("google", "/calendars/events", "DELETE") == "buffer"

    def test_high_risk_providers_always_buffer(self):
        assert classify_risk("salesforce", "/any/path", "GET") == "buffer"
        assert classify_risk("hubspot", "/any/path", "GET") == "buffer"

    def test_high_risk_paths_buffer(self):
        assert classify_risk("slack", "/conversations.history", "GET") == "buffer"
        assert classify_risk("google", "/drive/files/abc", "GET") == "buffer"
        assert classify_risk("microsoft", "/mail/messages/123", "GET") == "buffer"
        assert classify_risk("github", "/repos/x/files/y", "GET") == "buffer"

    def test_low_risk_get_streams(self):
        assert classify_risk("google", "/calendars/primary/events", "GET") == "stream"
        assert classify_risk("github", "/repos/owner/repo/issues", "GET") == "stream"

    def test_crm_paths_buffer(self):
        assert classify_risk("google", "/sobjects/Account/123", "GET") == "buffer"
        assert classify_risk("google", "/crm/v3/objects/contacts", "GET") == "buffer"

    def test_case_insensitive_paths(self):
        assert classify_risk("google", "/Mail/Messages/123", "GET") == "buffer"
        assert classify_risk("slack", "/Conversations.History", "GET") == "buffer"


# ── Edge cases ─────────────────────────────────────────────────────────


class TestStreamingEdgeCases:
    def test_empty_chunk(self):
        rule = _rule(checks=[_check_keyword("BAD")])
        sv = StreamingValidator([rule])

        result = sv.feed(b"")
        assert not result.should_terminate

    def test_no_rules(self):
        sv = StreamingValidator([])
        result = sv.feed(b"any content SECRET")
        assert not result.should_terminate
        final = sv.finalize()
        assert final.passed

    def test_binary_chunk_handled(self):
        rule = _rule(checks=[_check_keyword("BAD")])
        sv = StreamingValidator([rule])

        result = sv.feed(b"\x00\x01\x02\xff")
        assert not result.should_terminate

    def test_large_chunk_performance(self):
        """Ensure large chunks don't cause issues."""
        rule = _rule(checks=[_check_regex(r"needle_in_haystack")])
        sv = StreamingValidator([rule])

        big_chunk = b"x" * 100_000
        result = sv.feed(big_chunk)
        assert not result.should_terminate

        # Now send the needle
        result2 = sv.feed(b"needle_in_haystack")
        assert result2.should_terminate
