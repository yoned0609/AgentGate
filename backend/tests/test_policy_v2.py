"""Tests for policy engine v2 features: intent matching, hot reload, validation, conditions."""

import time
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

from app.policy import PolicyEngine, PolicyValidationError, _validate_policy_schema


# ── Helper ──────────────────────────────────────────────────────────


@dataclass
class FakeIntent:
    intent_type: str
    resource_type: str = "unknown"
    confidence: float = 0.9
    analysis_level: str = "L1"


def _write_policy(tmpdir: Path, name: str, data: dict) -> Path:
    p = tmpdir / f"{name}.yaml"
    p.write_text(yaml.dump(data), encoding="utf-8")
    return p


def _make_policy(tmpdir: Path, **overrides) -> PolicyEngine:
    base = {
        "name": "test",
        "description": "test policy",
        "rules": [
            {"resource": "/*", "methods": ["GET"], "effect": "allow"},
        ],
        "default_effect": "deny",
    }
    base.update(overrides)
    _write_policy(tmpdir, "test", base)
    return PolicyEngine(policy_dir=str(tmpdir))


# ── Intent-based matching ───────────────────────────────────────────


class TestIntentMatching:
    def test_intent_rule_allows_read(self, tmp_path):
        _write_policy(
            tmp_path,
            "intent_pol",
            {
                "name": "intent_pol",
                "rules": [
                    {"intent": "read", "effect": "allow"},
                    {"intent": "delete", "effect": "deny", "reason": "No deletes"},
                ],
                "default_effect": "deny",
            },
        )
        engine = PolicyEngine(policy_dir=str(tmp_path))
        intent = FakeIntent(intent_type="read")
        decision = engine.evaluate("intent_pol", "GET", "/anything", intent=intent)
        assert decision.effect == "allow"

    def test_intent_rule_denies_delete(self, tmp_path):
        _write_policy(
            tmp_path,
            "intent_pol",
            {
                "name": "intent_pol",
                "rules": [
                    {"intent": "read", "effect": "allow"},
                    {"intent": "delete", "effect": "deny", "reason": "No deletes"},
                ],
                "default_effect": "deny",
            },
        )
        engine = PolicyEngine(policy_dir=str(tmp_path))
        intent = FakeIntent(intent_type="delete")
        decision = engine.evaluate("intent_pol", "DELETE", "/x", intent=intent)
        assert decision.effect == "deny"
        assert decision.reason == "No deletes"

    def test_intent_list_matching(self, tmp_path):
        _write_policy(
            tmp_path,
            "intent_list",
            {
                "name": "intent_list",
                "rules": [
                    {"intent": ["read", "query"], "effect": "allow"},
                ],
                "default_effect": "deny",
            },
        )
        engine = PolicyEngine(policy_dir=str(tmp_path))
        assert (
            engine.evaluate(
                "intent_list", "GET", "/x", intent=FakeIntent("query")
            ).effect
            == "allow"
        )
        assert (
            engine.evaluate(
                "intent_list", "POST", "/x", intent=FakeIntent("create")
            ).effect
            == "deny"
        )

    def test_intent_with_resource_combined(self, tmp_path):
        _write_policy(
            tmp_path,
            "combined",
            {
                "name": "combined",
                "rules": [
                    {
                        "resource": "/calendars/*",
                        "intent": "read",
                        "methods": ["GET"],
                        "effect": "allow",
                    },
                ],
                "default_effect": "deny",
            },
        )
        engine = PolicyEngine(policy_dir=str(tmp_path))
        intent = FakeIntent("read")
        # All criteria match
        assert (
            engine.evaluate(
                "combined", "GET", "/calendars/primary", intent=intent
            ).effect
            == "allow"
        )
        # Wrong intent
        assert (
            engine.evaluate(
                "combined", "GET", "/calendars/primary", intent=FakeIntent("delete")
            ).effect
            == "deny"
        )
        # Wrong path
        assert (
            engine.evaluate("combined", "GET", "/other/path", intent=intent).effect
            == "deny"
        )

    def test_no_intent_falls_through(self, tmp_path):
        """Intent rule should not match when no intent is provided."""
        _write_policy(
            tmp_path,
            "needsintent",
            {
                "name": "needsintent",
                "rules": [
                    {"intent": "read", "effect": "allow"},
                ],
                "default_effect": "deny",
            },
        )
        engine = PolicyEngine(policy_dir=str(tmp_path))
        decision = engine.evaluate("needsintent", "GET", "/x", intent=None)
        assert decision.effect == "deny"


# ── Hot reload ──────────────────────────────────────────────────────


class TestHotReload:
    def test_detects_modified_file(self, tmp_path):
        _write_policy(
            tmp_path,
            "hot",
            {
                "name": "hot",
                "rules": [{"resource": "/*", "methods": ["GET"], "effect": "deny"}],
                "default_effect": "deny",
            },
        )
        engine = PolicyEngine(policy_dir=str(tmp_path))
        assert engine.evaluate("hot", "GET", "/x").effect == "deny"

        # Modify the file
        time.sleep(0.05)
        _write_policy(
            tmp_path,
            "hot",
            {
                "name": "hot",
                "rules": [{"resource": "/*", "methods": ["GET"], "effect": "allow"}],
                "default_effect": "deny",
            },
        )
        assert engine.reload_if_changed()
        assert engine.evaluate("hot", "GET", "/x").effect == "allow"

    def test_no_change_returns_false(self, tmp_path):
        _make_policy(tmp_path)
        engine = PolicyEngine(policy_dir=str(tmp_path))
        assert not engine.reload_if_changed()

    def test_detects_new_file(self, tmp_path):
        _make_policy(tmp_path)
        engine = PolicyEngine(policy_dir=str(tmp_path))
        assert "newpol" not in engine.policy_names

        time.sleep(0.05)
        _write_policy(
            tmp_path,
            "newpol",
            {
                "name": "newpol",
                "rules": [{"resource": "/*", "methods": ["GET"], "effect": "allow"}],
                "default_effect": "deny",
            },
        )
        assert engine.reload_if_changed()
        assert "newpol" in engine.policy_names

    def test_detects_deleted_file(self, tmp_path):
        _write_policy(
            tmp_path,
            "ephemeral",
            {
                "name": "ephemeral",
                "rules": [{"resource": "/*", "methods": ["GET"], "effect": "allow"}],
                "default_effect": "deny",
            },
        )
        engine = PolicyEngine(policy_dir=str(tmp_path))
        assert "ephemeral" in engine.policy_names

        (tmp_path / "ephemeral.yaml").unlink()
        assert engine.reload_if_changed()
        assert "ephemeral" not in engine.policy_names


# ── Schema validation ──────────────────────────────────────────────


class TestSchemaValidation:
    def test_missing_name_raises(self):
        with pytest.raises(
            PolicyValidationError, match="missing required field 'name'"
        ):
            _validate_policy_schema({"rules": []}, "bad.yaml")

    def test_invalid_effect_raises(self):
        with pytest.raises(PolicyValidationError, match="default_effect"):
            _validate_policy_schema(
                {"name": "x", "default_effect": "maybe"}, "bad.yaml"
            )

    def test_rule_missing_effect_raises(self):
        with pytest.raises(PolicyValidationError, match="missing 'effect'"):
            _validate_policy_schema(
                {"name": "x", "rules": [{"resource": "/*", "methods": ["GET"]}]},
                "bad.yaml",
            )

    def test_rule_invalid_effect_raises(self):
        with pytest.raises(PolicyValidationError, match="effect must be"):
            _validate_policy_schema(
                {
                    "name": "x",
                    "rules": [
                        {"resource": "/*", "methods": ["GET"], "effect": "maybe"}
                    ],
                },
                "bad.yaml",
            )

    def test_rule_no_criteria_raises(self):
        with pytest.raises(PolicyValidationError, match="at least one of"):
            _validate_policy_schema(
                {"name": "x", "rules": [{"effect": "allow"}]}, "bad.yaml"
            )

    def test_invalid_rate_limit_raises(self):
        with pytest.raises(PolicyValidationError, match="requests_per_minute"):
            _validate_policy_schema(
                {"name": "x", "rate_limit": {"requests_per_minute": -1}}, "bad.yaml"
            )

    def test_valid_policy_passes(self, tmp_path):
        """A well-formed policy should load without errors."""
        engine = _make_policy(tmp_path)
        assert "test" in engine.policy_names

    def test_invalid_policy_skipped_on_load(self, tmp_path):
        """Invalid policy files are skipped, not crash the engine."""
        _write_policy(tmp_path, "bad", {"rules": []})  # Missing 'name'
        _write_policy(
            tmp_path,
            "good",
            {
                "name": "good",
                "rules": [{"resource": "/*", "methods": ["GET"], "effect": "allow"}],
            },
        )
        engine = PolicyEngine(policy_dir=str(tmp_path))
        assert "good" in engine.policy_names
        assert "bad" not in engine.policy_names


# ── Compound conditions ────────────────────────────────────────────


class TestCompoundConditions:
    def test_and_conditions(self, tmp_path):
        _write_policy(
            tmp_path,
            "cond",
            {
                "name": "cond",
                "rules": [
                    {
                        "effect": "allow",
                        "resource": "/*",
                        "conditions": {
                            "and": [
                                {"methods": ["GET"]},
                                {"intent": "read"},
                            ]
                        },
                    },
                ],
                "default_effect": "deny",
            },
        )
        engine = PolicyEngine(policy_dir=str(tmp_path))
        # Both conditions met
        assert (
            engine.evaluate("cond", "GET", "/x", intent=FakeIntent("read")).effect
            == "allow"
        )
        # Wrong method
        assert (
            engine.evaluate("cond", "POST", "/x", intent=FakeIntent("read")).effect
            == "deny"
        )
        # Wrong intent
        assert (
            engine.evaluate("cond", "GET", "/x", intent=FakeIntent("delete")).effect
            == "deny"
        )

    def test_or_conditions(self, tmp_path):
        _write_policy(
            tmp_path,
            "orcond",
            {
                "name": "orcond",
                "rules": [
                    {
                        "effect": "allow",
                        "resource": "/*",
                        "conditions": {
                            "or": [
                                {"methods": ["GET"]},
                                {"intent": "read"},
                            ]
                        },
                    },
                ],
                "default_effect": "deny",
            },
        )
        engine = PolicyEngine(policy_dir=str(tmp_path))
        # GET matches first condition
        assert (
            engine.evaluate("orcond", "GET", "/x", intent=FakeIntent("create")).effect
            == "allow"
        )
        # POST+read matches second condition
        assert (
            engine.evaluate("orcond", "POST", "/x", intent=FakeIntent("read")).effect
            == "allow"
        )
        # Neither matches
        assert (
            engine.evaluate("orcond", "POST", "/x", intent=FakeIntent("create")).effect
            == "deny"
        )
