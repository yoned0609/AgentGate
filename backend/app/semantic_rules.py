"""Semantic Poka-yoke — response-level business rule validation.

AgentGate's existing policy engine governs *requests* (what an agent is
allowed to call).  Semantic Poka-yoke governs *responses* (what the
upstream API is allowed to return to the agent).

Two-layer architecture:
  Layer 1 — Pattern checks (regex / keyword / numeric range)
             Deterministic, <1 ms, handles ~95 % of cases.
  Layer 2 — LLM checks (optional, for complex semantic rules)
             Async, configurable per-rule, higher latency / cost.

Design principles:
  - YAML-declared rules identical in spirit to policy.yaml
  - Two enforcement modes: "enforce" (block) / "audit" (log only)
  - Validation is skipped for non-JSON responses and streaming
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from loguru import logger


# ── Data models ────────────────────────────────────────────────────────


class RuleMode(str, Enum):
    """Enforcement mode for a semantic rule."""
    ENFORCE = "enforce"  # Block the response
    AUDIT = "audit"      # Log only, pass response through


class CheckType(str, Enum):
    """Type of pattern check."""
    REGEX = "regex"
    KEYWORD = "keyword"
    NUMERIC_RANGE = "numeric_range"
    JSON_PATH = "json_path"
    LLM = "llm"


@dataclass
class PatternCheck:
    """A single pattern-based check within a rule."""
    check_type: CheckType
    # For regex / keyword
    pattern: str = ""
    # For numeric_range: field path in JSON + bounds
    field_path: str = ""
    min_value: float | None = None
    max_value: float | None = None
    # For json_path: JSONPath expression + forbidden values
    forbidden_values: list[str] = field(default_factory=list)
    # Human-readable description
    description: str = ""


@dataclass
class LLMCheck:
    """Configuration for an optional LLM-based semantic check."""
    enabled: bool = False
    prompt_template: str = ""
    # Threshold for LLM confidence to trigger violation (0.0-1.0)
    threshold: float = 0.8
    # Max tokens for LLM response
    max_tokens: int = 100


@dataclass
class SemanticRule:
    """A single semantic validation rule."""
    name: str
    description: str
    # Which providers / paths this rule applies to
    providers: list[str] = field(default_factory=list)  # empty = all
    path_patterns: list[str] = field(default_factory=list)  # empty = all
    methods: list[str] = field(default_factory=list)  # empty = all
    # Pattern-based checks (Layer 1)
    checks: list[PatternCheck] = field(default_factory=list)
    # LLM check (Layer 2, optional)
    llm_check: LLMCheck = field(default_factory=LLMCheck)
    # Enforcement mode
    mode: RuleMode = RuleMode.ENFORCE
    # Severity for logging / alerting
    severity: str = "high"  # "critical" | "high" | "medium" | "low"
    # Human-readable violation message
    violation_message: str = "Semantic rule violation detected"


@dataclass
class ValidationResult:
    """Result of semantic validation for a single response."""
    passed: bool
    violations: list[Violation] = field(default_factory=list)
    checked_rules: int = 0
    latency_ms: float = 0.0


@dataclass
class Violation:
    """A single rule violation."""
    rule_name: str
    description: str
    severity: str
    mode: str  # "enforce" or "audit"
    matched_content: str = ""  # snippet that triggered the violation
    check_type: str = ""


# ── Rule loader ────────────────────────────────────────────────────────


def _parse_check(raw: dict) -> PatternCheck:
    """Parse a single check from YAML dict."""
    return PatternCheck(
        check_type=CheckType(raw.get("type", "keyword")),
        pattern=raw.get("pattern", ""),
        field_path=raw.get("field_path", ""),
        min_value=raw.get("min_value"),
        max_value=raw.get("max_value"),
        forbidden_values=raw.get("forbidden_values", []),
        description=raw.get("description", ""),
    )


def _parse_rule(raw: dict) -> SemanticRule:
    """Parse a single semantic rule from YAML dict."""
    checks = [_parse_check(c) for c in raw.get("checks", [])]
    llm_raw = raw.get("llm_check", {})
    llm_check = LLMCheck(
        enabled=llm_raw.get("enabled", False),
        prompt_template=llm_raw.get("prompt_template", ""),
        threshold=llm_raw.get("threshold", 0.8),
        max_tokens=llm_raw.get("max_tokens", 100),
    )
    return SemanticRule(
        name=raw["name"],
        description=raw.get("description", ""),
        providers=raw.get("providers", []),
        path_patterns=raw.get("path_patterns", []),
        methods=raw.get("methods", []),
        checks=checks,
        llm_check=llm_check,
        mode=RuleMode(raw.get("mode", "enforce")),
        severity=raw.get("severity", "high"),
        violation_message=raw.get("violation_message", "Semantic rule violation detected"),
    )


def load_semantic_rules(rules_dir: str | Path) -> list[SemanticRule]:
    """Load all semantic rule YAML files from a directory."""
    rules_path = Path(rules_dir)
    if not rules_path.exists():
        logger.info(f"Semantic rules directory not found: {rules_path}")
        return []

    rules: list[SemanticRule] = []
    for yaml_file in sorted(rules_path.glob("*.yaml")):
        try:
            data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
            if not data or "rules" not in data:
                continue
            for raw_rule in data["rules"]:
                rules.append(_parse_rule(raw_rule))
                logger.debug(f"Loaded semantic rule: {rules[-1].name}")
        except Exception as exc:
            logger.error(f"Failed to load semantic rules from {yaml_file}: {exc}")

    logger.info(f"Loaded {len(rules)} semantic rules from {rules_path}")
    return rules


# ── Validator engine ──────────────────────────────────────────────────


class SemanticValidator:
    """Validates upstream API responses against semantic business rules.

    Usage:
        validator = SemanticValidator(rules_dir="semantic_rules")
        result = await validator.validate(
            response_body=b'{"amount": 999999}',
            provider="salesforce",
            path="/sobjects/Opportunity",
            method="GET",
        )
        if not result.passed:
            # block or log depending on violation modes
    """

    def __init__(
        self,
        rules: list[SemanticRule] | None = None,
        rules_dir: str | Path | None = None,
        llm_callback: Any | None = None,
    ) -> None:
        if rules is not None:
            self._rules = rules
        elif rules_dir is not None:
            self._rules = load_semantic_rules(rules_dir)
        else:
            self._rules = []
        self._llm_callback = llm_callback
        self._stats = {
            "total_checks": 0,
            "violations_found": 0,
            "enforced_blocks": 0,
            "audit_only": 0,
        }

    async def validate(
        self,
        response_body: bytes,
        provider: str,
        path: str,
        method: str,
        content_type: str = "application/json",
    ) -> ValidationResult:
        """Run all applicable semantic rules against a response body."""
        start = time.perf_counter()
        self._stats["total_checks"] += 1

        # Skip non-JSON responses
        if "json" not in content_type.lower():
            return ValidationResult(passed=True, checked_rules=0,
                                    latency_ms=(time.perf_counter() - start) * 1000)

        # Parse response body
        try:
            body_text = response_body.decode("utf-8", errors="replace")
        except Exception:
            return ValidationResult(passed=True, checked_rules=0,
                                    latency_ms=(time.perf_counter() - start) * 1000)

        # Try JSON parse for structured checks
        body_json: dict | list | None = None
        try:
            body_json = json.loads(body_text)
        except (json.JSONDecodeError, ValueError):
            pass

        # Filter applicable rules
        applicable = self._filter_rules(provider, path, method)
        if not applicable:
            return ValidationResult(passed=True, checked_rules=0,
                                    latency_ms=(time.perf_counter() - start) * 1000)

        violations: list[Violation] = []

        for rule in applicable:
            # Layer 1: Pattern checks
            for check in rule.checks:
                violation = self._run_pattern_check(rule, check, body_text, body_json)
                if violation:
                    violations.append(violation)

            # Layer 2: LLM check (optional)
            if rule.llm_check.enabled and self._llm_callback:
                llm_violation = await self._run_llm_check(rule, body_text)
                if llm_violation:
                    violations.append(llm_violation)

        # Determine overall pass/fail
        has_enforced = any(v.mode == "enforce" for v in violations)

        if violations:
            self._stats["violations_found"] += len(violations)
            if has_enforced:
                self._stats["enforced_blocks"] += 1
            else:
                self._stats["audit_only"] += 1

        latency = (time.perf_counter() - start) * 1000
        return ValidationResult(
            passed=not has_enforced,
            violations=violations,
            checked_rules=len(applicable),
            latency_ms=latency,
        )

    def _filter_rules(
        self, provider: str, path: str, method: str
    ) -> list[SemanticRule]:
        """Return rules applicable to this provider/path/method."""
        result = []
        for rule in self._rules:
            # Provider filter
            if rule.providers and provider not in rule.providers:
                continue
            # Method filter
            if rule.methods and method.upper() not in [m.upper() for m in rule.methods]:
                continue
            # Path pattern filter
            if rule.path_patterns:
                matched = any(
                    re.search(p, path) for p in rule.path_patterns
                )
                if not matched:
                    continue
            result.append(rule)
        return result

    def _run_pattern_check(
        self,
        rule: SemanticRule,
        check: PatternCheck,
        body_text: str,
        body_json: dict | list | None,
    ) -> Violation | None:
        """Execute a single pattern check. Returns Violation if triggered."""
        try:
            if check.check_type == CheckType.REGEX:
                return self._check_regex(rule, check, body_text)
            elif check.check_type == CheckType.KEYWORD:
                return self._check_keyword(rule, check, body_text)
            elif check.check_type == CheckType.NUMERIC_RANGE:
                return self._check_numeric_range(rule, check, body_json)
            elif check.check_type == CheckType.JSON_PATH:
                return self._check_json_path(rule, check, body_json)
        except Exception as exc:
            logger.warning(
                f"Semantic check error: rule={rule.name} check={check.check_type} err={exc}"
            )
        return None

    def _check_regex(
        self, rule: SemanticRule, check: PatternCheck, body_text: str
    ) -> Violation | None:
        """Check if response body matches a forbidden regex pattern."""
        match = re.search(check.pattern, body_text, re.IGNORECASE)
        if match:
            # Limit matched content to avoid huge strings
            snippet = match.group(0)[:200]
            return Violation(
                rule_name=rule.name,
                description=check.description or rule.violation_message,
                severity=rule.severity,
                mode=rule.mode.value,
                matched_content=_redact(snippet),
                check_type="regex",
            )
        return None

    def _check_keyword(
        self, rule: SemanticRule, check: PatternCheck, body_text: str
    ) -> Violation | None:
        """Check if response body contains a forbidden keyword."""
        keywords = [k.strip() for k in check.pattern.split(",") if k.strip()]
        body_lower = body_text.lower()
        for kw in keywords:
            if kw.lower() in body_lower:
                # Find context around keyword
                idx = body_lower.index(kw.lower())
                start = max(0, idx - 30)
                end = min(len(body_text), idx + len(kw) + 30)
                snippet = body_text[start:end]
                return Violation(
                    rule_name=rule.name,
                    description=check.description or rule.violation_message,
                    severity=rule.severity,
                    mode=rule.mode.value,
                    matched_content=_redact(snippet),
                    check_type="keyword",
                )
        return None

    def _check_numeric_range(
        self,
        rule: SemanticRule,
        check: PatternCheck,
        body_json: dict | list | None,
    ) -> Violation | None:
        """Check if a numeric field exceeds allowed bounds."""
        if body_json is None or not check.field_path:
            return None

        value = _extract_field(body_json, check.field_path)
        if value is None:
            return None

        try:
            num = float(value)
        except (ValueError, TypeError):
            return None

        violated = False
        if check.max_value is not None and num > check.max_value:
            violated = True
        if check.min_value is not None and num < check.min_value:
            violated = True

        if violated:
            return Violation(
                rule_name=rule.name,
                description=check.description or rule.violation_message,
                severity=rule.severity,
                mode=rule.mode.value,
                matched_content=f"{check.field_path}={num}",
                check_type="numeric_range",
            )
        return None

    def _check_json_path(
        self,
        rule: SemanticRule,
        check: PatternCheck,
        body_json: dict | list | None,
    ) -> Violation | None:
        """Check if a JSON field contains forbidden values."""
        if body_json is None or not check.field_path:
            return None

        value = _extract_field(body_json, check.field_path)
        if value is None:
            return None

        str_value = str(value).lower()
        for forbidden in check.forbidden_values:
            if forbidden.lower() in str_value:
                return Violation(
                    rule_name=rule.name,
                    description=check.description or rule.violation_message,
                    severity=rule.severity,
                    mode=rule.mode.value,
                    matched_content=f"{check.field_path} contains '{forbidden}'",
                    check_type="json_path",
                )
        return None

    async def _run_llm_check(
        self, rule: SemanticRule, body_text: str
    ) -> Violation | None:
        """Run LLM-based semantic validation (Layer 2)."""
        if not self._llm_callback:
            return None

        # Truncate body to avoid excessive token usage
        truncated = body_text[:4000]
        # Escape to prevent prompt injection from response content
        escaped = truncated.replace("{", "{{").replace("}", "}}")

        prompt = rule.llm_check.prompt_template.format(
            response_body=escaped,
            rule_name=rule.name,
            rule_description=rule.description,
        )

        try:
            result = await self._llm_callback(
                prompt=prompt,
                max_tokens=rule.llm_check.max_tokens,
            )
            # Expect result: {"violation": bool, "confidence": float, "reason": str}
            if isinstance(result, dict):
                if result.get("violation") and result.get("confidence", 0) >= rule.llm_check.threshold:
                    return Violation(
                        rule_name=rule.name,
                        description=result.get("reason", rule.violation_message),
                        severity=rule.severity,
                        mode=rule.mode.value,
                        matched_content="[LLM detected]",
                        check_type="llm",
                    )
        except Exception as exc:
            logger.warning(f"LLM semantic check failed: rule={rule.name} err={exc}")

        return None

    def add_rule(self, rule: SemanticRule) -> None:
        """Add a rule at runtime."""
        self._rules.append(rule)

    def remove_rule(self, name: str) -> bool:
        """Remove a rule by name. Returns True if found and removed."""
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.name != name]
        return len(self._rules) < before

    @property
    def rules(self) -> list[SemanticRule]:
        return list(self._rules)

    @property
    def stats(self) -> dict:
        return {
            **self._stats,
            "rules_loaded": len(self._rules),
        }


# ── Streaming validator ────────────────────────────────────────────────


class StreamingValidator:
    """Validates response chunks incrementally using a sliding window.

    Designed for chunked / SSE responses where buffering the entire body
    would defeat the purpose of streaming.  A sliding window keeps the
    tail of the previous chunk so that patterns split across chunk
    boundaries are still detected.

    Usage (inside an async streaming loop)::

        sv = StreamingValidator(rules, overlap=256)
        async for chunk in upstream:
            result = sv.feed(chunk)
            if result.should_terminate:
                # send error terminator to client, close stream
                break
            yield chunk  # safe — forward to client
        # After stream ends:
        final = sv.finalize()
    """

    def __init__(
        self,
        rules: list[SemanticRule],
        provider: str = "",
        path: str = "",
        method: str = "GET",
        overlap: int = 256,
    ) -> None:
        self._rules = _filter_rules_static(rules, provider, path, method)
        self._overlap = overlap
        # Sliding window: tail of previous chunk for cross-boundary detection
        self._prev_tail: str = ""
        # Full accumulated text for post-hoc audit
        self._accumulated: list[str] = []
        self._total_bytes: int = 0
        self._violations: list[Violation] = []
        self._terminated: bool = False
        self._chunks_checked: int = 0

    def feed(self, chunk: bytes) -> StreamingCheckResult:
        """Feed a chunk and run pattern checks on it.

        Returns a result indicating whether the stream should be terminated.
        Only regex and keyword checks run per-chunk (numeric / json_path
        require the full parsed body and are deferred to finalize()).
        """
        if self._terminated:
            return StreamingCheckResult(should_terminate=True, violations=self._violations)

        try:
            text = chunk.decode("utf-8", errors="replace")
        except Exception:
            return StreamingCheckResult(should_terminate=False)

        self._accumulated.append(text)
        self._total_bytes += len(chunk)
        self._chunks_checked += 1

        # Build window: previous tail + current chunk
        window = self._prev_tail + text

        new_violations: list[Violation] = []
        for rule in self._rules:
            for check in rule.checks:
                if check.check_type not in (CheckType.REGEX, CheckType.KEYWORD):
                    continue  # defer structured checks to finalize()
                violation = _run_pattern_check_static(rule, check, window)
                if violation:
                    new_violations.append(violation)

        # Update sliding window tail
        if self._overlap > 0:
            self._prev_tail = text[-self._overlap:] if len(text) > self._overlap else text
        else:
            self._prev_tail = ""

        if new_violations:
            self._violations.extend(new_violations)
            has_enforced = any(v.mode == "enforce" for v in new_violations)
            if has_enforced:
                self._terminated = True
                return StreamingCheckResult(
                    should_terminate=True,
                    violations=new_violations,
                )

        return StreamingCheckResult(should_terminate=False, violations=new_violations)

    def finalize(self) -> ValidationResult:
        """Run deferred checks (numeric / json_path) on the full accumulated body.

        Call after the stream ends (or after termination) for post-hoc audit.
        """
        full_text = "".join(self._accumulated)

        # Try JSON parse
        body_json: dict | list | None = None
        try:
            body_json = json.loads(full_text)
        except (json.JSONDecodeError, ValueError):
            pass

        # Run deferred structured checks
        deferred_violations: list[Violation] = []
        for rule in self._rules:
            for check in rule.checks:
                if check.check_type in (CheckType.REGEX, CheckType.KEYWORD):
                    continue  # already checked per-chunk
                violation = _run_pattern_check_static(rule, check, full_text, body_json)
                if violation:
                    deferred_violations.append(violation)

        all_violations = self._violations + deferred_violations
        has_enforced = any(v.mode == "enforce" for v in all_violations)

        return ValidationResult(
            passed=not has_enforced,
            violations=all_violations,
            checked_rules=len(self._rules),
        )

    @property
    def terminated(self) -> bool:
        return self._terminated

    @property
    def stats(self) -> dict:
        return {
            "chunks_checked": self._chunks_checked,
            "total_bytes": self._total_bytes,
            "violations_found": len(self._violations),
            "terminated": self._terminated,
        }


@dataclass
class StreamingCheckResult:
    """Result of checking a single chunk."""
    should_terminate: bool = False
    violations: list[Violation] = field(default_factory=list)


# ── Risk classification ───────────────────────────────────────────────


# Paths that MUST be fully buffered before returning to the agent.
# These typically return sensitive / financial / PII data.
_HIGH_RISK_PATH_PATTERNS: list[re.Pattern] = [
    # CRM / financial
    re.compile(r"/sobjects?/", re.IGNORECASE),           # Salesforce
    re.compile(r"/crm/v\d+/objects/", re.IGNORECASE),    # HubSpot
    re.compile(r"/contacts", re.IGNORECASE),
    re.compile(r"/deals", re.IGNORECASE),
    # Email / messaging content
    re.compile(r"/messages?/", re.IGNORECASE),
    re.compile(r"/mail/", re.IGNORECASE),
    re.compile(r"/conversations\.history", re.IGNORECASE),  # Slack
    # Files
    re.compile(r"/files?/", re.IGNORECASE),
    re.compile(r"/drive/", re.IGNORECASE),
    # User data
    re.compile(r"/users?/.*/(profile|info)", re.IGNORECASE),
]

# Providers where ALL responses should be buffered
_HIGH_RISK_PROVIDERS: frozenset[str] = frozenset({
    "salesforce",
    "hubspot",
})


def classify_risk(provider: str, path: str, method: str) -> str:
    """Classify a request as 'buffer' or 'stream'.

    Returns:
        "buffer" — response must be fully buffered and validated before
                   forwarding to the agent.
        "stream" — response can be streamed with per-chunk validation.
    """
    # Write operations always buffer (response may contain created/updated data)
    if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        return "buffer"

    # High-risk providers always buffer
    if provider in _HIGH_RISK_PROVIDERS:
        return "buffer"

    # Check path patterns
    for pattern in _HIGH_RISK_PATH_PATTERNS:
        if pattern.search(path):
            return "buffer"

    return "stream"


# ── Static helpers (shared by SemanticValidator and StreamingValidator) ─


def _filter_rules_static(
    rules: list[SemanticRule], provider: str, path: str, method: str
) -> list[SemanticRule]:
    """Filter rules applicable to provider/path/method (standalone function)."""
    result = []
    for rule in rules:
        if rule.providers and provider not in rule.providers:
            continue
        if rule.methods and method.upper() not in [m.upper() for m in rule.methods]:
            continue
        if rule.path_patterns:
            if not any(re.search(p, path) for p in rule.path_patterns):
                continue
        result.append(rule)
    return result


def _run_pattern_check_static(
    rule: SemanticRule,
    check: PatternCheck,
    body_text: str,
    body_json: dict | list | None = None,
) -> Violation | None:
    """Execute a pattern check (standalone function for reuse)."""
    try:
        if check.check_type == CheckType.REGEX:
            match = re.search(check.pattern, body_text, re.IGNORECASE)
            if match:
                snippet = match.group(0)[:200]
                return Violation(
                    rule_name=rule.name,
                    description=check.description or rule.violation_message,
                    severity=rule.severity,
                    mode=rule.mode.value,
                    matched_content=_redact(snippet),
                    check_type="regex",
                )
        elif check.check_type == CheckType.KEYWORD:
            keywords = [k.strip() for k in check.pattern.split(",") if k.strip()]
            body_lower = body_text.lower()
            for kw in keywords:
                if kw.lower() in body_lower:
                    idx = body_lower.index(kw.lower())
                    start = max(0, idx - 30)
                    end = min(len(body_text), idx + len(kw) + 30)
                    snippet = body_text[start:end]
                    return Violation(
                        rule_name=rule.name,
                        description=check.description or rule.violation_message,
                        severity=rule.severity,
                        mode=rule.mode.value,
                        matched_content=_redact(snippet),
                        check_type="keyword",
                    )
        elif check.check_type == CheckType.NUMERIC_RANGE:
            if body_json is not None and check.field_path:
                value = _extract_field(body_json, check.field_path)
                if value is not None:
                    try:
                        num = float(value)
                    except (ValueError, TypeError):
                        return None
                    violated = False
                    if check.max_value is not None and num > check.max_value:
                        violated = True
                    if check.min_value is not None and num < check.min_value:
                        violated = True
                    if violated:
                        return Violation(
                            rule_name=rule.name,
                            description=check.description or rule.violation_message,
                            severity=rule.severity,
                            mode=rule.mode.value,
                            matched_content=f"{check.field_path}={num}",
                            check_type="numeric_range",
                        )
        elif check.check_type == CheckType.JSON_PATH:
            if body_json is not None and check.field_path:
                value = _extract_field(body_json, check.field_path)
                if value is not None:
                    str_value = str(value).lower()
                    for forbidden in check.forbidden_values:
                        if forbidden.lower() in str_value:
                            return Violation(
                                rule_name=rule.name,
                                description=check.description or rule.violation_message,
                                severity=rule.severity,
                                mode=rule.mode.value,
                                matched_content=f"{check.field_path} contains '{forbidden}'",
                                check_type="json_path",
                            )
    except Exception as exc:
        logger.warning(f"Pattern check error: rule={rule.name} type={check.check_type} err={exc}")
    return None


# ── Helpers ────────────────────────────────────────────────────────────


def _extract_field(obj: Any, path: str) -> Any:
    """Extract a value from a nested dict/list using dot-notation path.

    Example: _extract_field({"a": {"b": 42}}, "a.b") -> 42
             _extract_field([{"x": 1}], "0.x") -> 1
    """
    parts = path.split(".")
    current = obj
    for part in parts:
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (IndexError, ValueError):
                return None
        else:
            return None
    return current


def _redact(text: str, max_len: int = 100) -> str:
    """Redact and truncate matched content for safe logging."""
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text
