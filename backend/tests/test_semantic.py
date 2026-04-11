"""Tests for Semantic Poka-yoke — response-level business rule validation."""

import json
import pytest
from app.semantic_rules import (
    CheckType,
    LLMCheck,
    PatternCheck,
    RuleMode,
    SemanticRule,
    SemanticValidator,
    ValidationResult,
    Violation,
    _extract_field,
    load_semantic_rules,
)


# ── Helpers ────────────────────────────────────────────────────────────


def _rule(
    name: str = "test_rule",
    checks: list[PatternCheck] | None = None,
    mode: RuleMode = RuleMode.ENFORCE,
    providers: list[str] | None = None,
    methods: list[str] | None = None,
    path_patterns: list[str] | None = None,
    severity: str = "high",
) -> SemanticRule:
    return SemanticRule(
        name=name,
        description=f"Test rule: {name}",
        providers=providers or [],
        path_patterns=path_patterns or [],
        methods=methods or [],
        checks=checks or [],
        mode=mode,
        severity=severity,
        violation_message=f"Violation: {name}",
    )


def _check_regex(pattern: str, desc: str = "") -> PatternCheck:
    return PatternCheck(check_type=CheckType.REGEX, pattern=pattern, description=desc)


def _check_keyword(keywords: str, desc: str = "") -> PatternCheck:
    return PatternCheck(check_type=CheckType.KEYWORD, pattern=keywords, description=desc)


def _check_numeric(field_path: str, max_value: float | None = None, min_value: float | None = None) -> PatternCheck:
    return PatternCheck(
        check_type=CheckType.NUMERIC_RANGE,
        field_path=field_path,
        max_value=max_value,
        min_value=min_value,
    )


def _check_json_path(field_path: str, forbidden: list[str]) -> PatternCheck:
    return PatternCheck(
        check_type=CheckType.JSON_PATH,
        field_path=field_path,
        forbidden_values=forbidden,
    )


# ── Unit tests: _extract_field ─────────────────────────────────────


class TestExtractField:
    def test_simple_key(self):
        assert _extract_field({"name": "Alice"}, "name") == "Alice"

    def test_nested_key(self):
        assert _extract_field({"a": {"b": {"c": 42}}}, "a.b.c") == 42

    def test_list_index(self):
        assert _extract_field([{"x": 1}, {"x": 2}], "1.x") == 2

    def test_missing_key(self):
        assert _extract_field({"a": 1}, "b") is None

    def test_none_input(self):
        assert _extract_field(None, "a") is None

    def test_deep_missing(self):
        assert _extract_field({"a": {"b": 1}}, "a.c.d") is None


# ── Unit tests: Pattern checks ─────────────────────────────────────


class TestRegexCheck:
    @pytest.mark.asyncio
    async def test_credit_card_detected(self):
        rule = _rule(checks=[_check_regex(r"\b4[0-9]{12}(?:[0-9]{3})?\b")])
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"card": "4111111111111111"}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert not result.passed
        assert len(result.violations) == 1
        assert result.violations[0].check_type == "regex"

    @pytest.mark.asyncio
    async def test_no_match_passes(self):
        rule = _rule(checks=[_check_regex(r"\b4[0-9]{15}\b")])
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"data": "hello world"}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert result.passed
        assert len(result.violations) == 0

    @pytest.mark.asyncio
    async def test_ssn_pattern(self):
        rule = _rule(checks=[_check_regex(r"\b\d{3}-\d{2}-\d{4}\b")])
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"ssn": "123-45-6789"}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert not result.passed


class TestKeywordCheck:
    @pytest.mark.asyncio
    async def test_keyword_found(self):
        rule = _rule(checks=[_check_keyword("CONFIDENTIAL,TOP SECRET")])
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"note": "This is CONFIDENTIAL data"}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert not result.passed
        assert result.violations[0].check_type == "keyword"

    @pytest.mark.asyncio
    async def test_keyword_case_insensitive(self):
        rule = _rule(checks=[_check_keyword("secret")])
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"note": "This is a SECRET document"}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert not result.passed

    @pytest.mark.asyncio
    async def test_keyword_not_found(self):
        rule = _rule(checks=[_check_keyword("CONFIDENTIAL,TOP SECRET")])
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"note": "Public information"}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert result.passed

    @pytest.mark.asyncio
    async def test_japanese_keyword(self):
        rule = _rule(checks=[_check_keyword("社外秘,極秘")])
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"doc": "この文書は社外秘です"}, ensure_ascii=False).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert not result.passed


class TestNumericRangeCheck:
    @pytest.mark.asyncio
    async def test_exceeds_max(self):
        rule = _rule(checks=[_check_numeric("amount", max_value=1000000)])
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"amount": 5000000}).encode()
        result = await v.validate(body, "salesforce", "/test", "GET")
        assert not result.passed
        assert result.violations[0].check_type == "numeric_range"

    @pytest.mark.asyncio
    async def test_within_range(self):
        rule = _rule(checks=[_check_numeric("amount", max_value=1000000)])
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"amount": 500}).encode()
        result = await v.validate(body, "salesforce", "/test", "GET")
        assert result.passed

    @pytest.mark.asyncio
    async def test_below_min(self):
        rule = _rule(checks=[_check_numeric("price", min_value=0)])
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"price": -100}).encode()
        result = await v.validate(body, "salesforce", "/test", "GET")
        assert not result.passed

    @pytest.mark.asyncio
    async def test_nested_field(self):
        rule = _rule(checks=[_check_numeric("order.total", max_value=100)])
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"order": {"total": 999}}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert not result.passed

    @pytest.mark.asyncio
    async def test_missing_field_passes(self):
        rule = _rule(checks=[_check_numeric("amount", max_value=100)])
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"name": "test"}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert result.passed


class TestJsonPathCheck:
    @pytest.mark.asyncio
    async def test_forbidden_value_found(self):
        rule = _rule(checks=[_check_json_path("status", ["deleted", "suspended"])])
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"status": "deleted"}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert not result.passed
        assert result.violations[0].check_type == "json_path"

    @pytest.mark.asyncio
    async def test_allowed_value_passes(self):
        rule = _rule(checks=[_check_json_path("status", ["deleted", "suspended"])])
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"status": "active"}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert result.passed


# ── Filtering tests ────────────────────────────────────────────────


class TestRuleFiltering:
    @pytest.mark.asyncio
    async def test_provider_filter(self):
        rule = _rule(
            providers=["salesforce"],
            checks=[_check_keyword("secret")],
        )
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"note": "secret data"}).encode()

        # Should NOT trigger for google
        result = await v.validate(body, "google", "/test", "GET")
        assert result.passed

        # Should trigger for salesforce
        result = await v.validate(body, "salesforce", "/test", "GET")
        assert not result.passed

    @pytest.mark.asyncio
    async def test_method_filter(self):
        rule = _rule(
            methods=["GET"],
            checks=[_check_keyword("secret")],
        )
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"note": "secret data"}).encode()

        # Should trigger for GET
        result = await v.validate(body, "google", "/test", "GET")
        assert not result.passed

        # Should NOT trigger for POST
        result = await v.validate(body, "google", "/test", "POST")
        assert result.passed

    @pytest.mark.asyncio
    async def test_path_pattern_filter(self):
        rule = _rule(
            path_patterns=[r"/calendars/.*"],
            checks=[_check_keyword("secret")],
        )
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"note": "secret data"}).encode()

        # Should trigger
        result = await v.validate(body, "google", "/calendars/primary/events", "GET")
        assert not result.passed

        # Should NOT trigger
        result = await v.validate(body, "google", "/users/me", "GET")
        assert result.passed


# ── Enforcement mode tests ─────────────────────────────────────────


class TestEnforcementModes:
    @pytest.mark.asyncio
    async def test_enforce_blocks(self):
        rule = _rule(mode=RuleMode.ENFORCE, checks=[_check_keyword("blocked")])
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"data": "blocked content"}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert not result.passed
        assert result.violations[0].mode == "enforce"

    @pytest.mark.asyncio
    async def test_audit_does_not_block(self):
        rule = _rule(mode=RuleMode.AUDIT, checks=[_check_keyword("flagged")])
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"data": "flagged content"}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        # passed=True because audit mode doesn't block
        assert result.passed
        # But violation is still recorded
        assert len(result.violations) == 1
        assert result.violations[0].mode == "audit"

    @pytest.mark.asyncio
    async def test_mixed_modes(self):
        """If one rule enforces and another audits, the response is blocked."""
        audit_rule = _rule(name="audit_rule", mode=RuleMode.AUDIT, checks=[_check_keyword("data")])
        enforce_rule = _rule(name="enforce_rule", mode=RuleMode.ENFORCE, checks=[_check_keyword("secret")])
        v = SemanticValidator(rules=[audit_rule, enforce_rule])
        body = json.dumps({"note": "secret data here"}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert not result.passed
        assert len(result.violations) == 2


# ── Non-JSON / Edge cases ──────────────────────────────────────────


class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_non_json_content_type_skipped(self):
        rule = _rule(checks=[_check_keyword("secret")])
        v = SemanticValidator(rules=[rule])
        body = b"secret plain text"
        result = await v.validate(body, "google", "/test", "GET", content_type="text/html")
        assert result.passed

    @pytest.mark.asyncio
    async def test_empty_body(self):
        rule = _rule(checks=[_check_keyword("secret")])
        v = SemanticValidator(rules=[rule])
        result = await v.validate(b"", "google", "/test", "GET")
        assert result.passed

    @pytest.mark.asyncio
    async def test_invalid_json_body_still_checks_text(self):
        """Even if JSON parsing fails, regex/keyword checks still run on raw text."""
        rule = _rule(checks=[_check_keyword("secret")])
        v = SemanticValidator(rules=[rule])
        body = b'not json but contains secret'
        result = await v.validate(body, "google", "/test", "GET")
        assert not result.passed

    @pytest.mark.asyncio
    async def test_no_rules_always_passes(self):
        v = SemanticValidator(rules=[])
        body = json.dumps({"anything": "at all"}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert result.passed
        assert result.checked_rules == 0


# ── Stats tracking ─────────────────────────────────────────────────


class TestStats:
    @pytest.mark.asyncio
    async def test_stats_tracking(self):
        rule = _rule(checks=[_check_keyword("bad")])
        v = SemanticValidator(rules=[rule])

        await v.validate(json.dumps({"ok": "good"}).encode(), "g", "/", "GET")
        await v.validate(json.dumps({"ok": "bad"}).encode(), "g", "/", "GET")

        stats = v.stats
        assert stats["total_checks"] == 2
        assert stats["violations_found"] == 1
        assert stats["enforced_blocks"] == 1
        assert stats["rules_loaded"] == 1


# ── Runtime rule management ────────────────────────────────────────


class TestRuleManagement:
    def test_add_rule(self):
        v = SemanticValidator(rules=[])
        assert len(v.rules) == 0
        v.add_rule(_rule(name="new_rule"))
        assert len(v.rules) == 1

    def test_remove_rule(self):
        v = SemanticValidator(rules=[_rule(name="to_remove")])
        assert len(v.rules) == 1
        assert v.remove_rule("to_remove")
        assert len(v.rules) == 0

    def test_remove_nonexistent(self):
        v = SemanticValidator(rules=[])
        assert not v.remove_rule("does_not_exist")


# ── LLM check (mock) ──────────────────────────────────────────────


class TestLLMCheck:
    @pytest.mark.asyncio
    async def test_llm_violation_detected(self):
        async def mock_llm(prompt: str, max_tokens: int) -> dict:
            return {"violation": True, "confidence": 0.95, "reason": "LLM says bad"}

        rule = SemanticRule(
            name="llm_rule",
            description="LLM-validated rule",
            checks=[],
            llm_check=LLMCheck(
                enabled=True,
                prompt_template="Check: {response_body}",
                threshold=0.8,
            ),
            mode=RuleMode.ENFORCE,
        )
        v = SemanticValidator(rules=[rule], llm_callback=mock_llm)
        body = json.dumps({"data": "something"}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert not result.passed
        assert result.violations[0].check_type == "llm"

    @pytest.mark.asyncio
    async def test_llm_below_threshold_passes(self):
        async def mock_llm(prompt: str, max_tokens: int) -> dict:
            return {"violation": True, "confidence": 0.5, "reason": "Not sure"}

        rule = SemanticRule(
            name="llm_rule",
            description="LLM-validated rule",
            checks=[],
            llm_check=LLMCheck(
                enabled=True,
                prompt_template="Check: {response_body}",
                threshold=0.8,
            ),
            mode=RuleMode.ENFORCE,
        )
        v = SemanticValidator(rules=[rule], llm_callback=mock_llm)
        body = json.dumps({"data": "something"}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert result.passed

    @pytest.mark.asyncio
    async def test_llm_disabled_skipped(self):
        call_count = 0

        async def mock_llm(prompt: str, max_tokens: int) -> dict:
            nonlocal call_count
            call_count += 1
            return {"violation": True, "confidence": 1.0, "reason": "bad"}

        rule = SemanticRule(
            name="llm_rule",
            description="LLM-validated rule",
            checks=[],
            llm_check=LLMCheck(enabled=False),
            mode=RuleMode.ENFORCE,
        )
        v = SemanticValidator(rules=[rule], llm_callback=mock_llm)
        body = json.dumps({"data": "something"}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert result.passed
        assert call_count == 0


# ── YAML loading ───────────────────────────────────────────────────


class TestYAMLLoading:
    def test_load_default_rules(self):
        rules = load_semantic_rules("semantic_rules")
        assert len(rules) > 0
        names = [r.name for r in rules]
        assert "pii_credit_card" in names
        assert "secret_api_key" in names

    def test_load_nonexistent_dir(self):
        rules = load_semantic_rules("/nonexistent/path")
        assert rules == []


# ── Integration: multiple checks per rule ──────────────────────────


class TestMultipleChecks:
    @pytest.mark.asyncio
    async def test_first_check_triggers(self):
        """If the first check matches, we get a violation even if second doesn't."""
        rule = _rule(checks=[
            _check_keyword("bad"),
            _check_keyword("also_bad"),
        ])
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"note": "this is bad"}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert not result.passed
        # Only the first matching check should produce a violation
        assert len(result.violations) == 1

    @pytest.mark.asyncio
    async def test_both_checks_trigger(self):
        rule = _rule(checks=[
            _check_keyword("bad"),
            _check_keyword("evil"),
        ])
        v = SemanticValidator(rules=[rule])
        body = json.dumps({"note": "bad and evil"}).encode()
        result = await v.validate(body, "google", "/test", "GET")
        assert not result.passed
        assert len(result.violations) == 2
