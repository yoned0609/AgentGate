"""Tests for P0 countermeasures:
1. L3 escalation → webhook integration
2. Workflow-level authorization engine
3. New provider policies (hubspot, salesforce, linear, aws)
4. E2E analytics + policy builder endpoint validation
"""

from __future__ import annotations

import asyncio
import time
import pytest
import sys
from pathlib import Path
from unittest.mock import AsyncMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.intent import IntentAnalyzer, IntentResult
from app.policy import PolicyEngine
from app.workflow import WorkflowEngine, WorkflowRule, DEFAULT_WORKFLOW_RULES
from app.l3_escalation import L3EscalationManager
from app.webhook import WebhookNotifier
from app.analytics import AnalyticsEngine
from app.policy_builder import PolicyBuildRequest, build_policy


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 1. Workflow Engine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestWorkflowEngine:
    """Test multi-step workflow authorization."""

    @pytest.fixture
    def engine(self):
        return WorkflowEngine()

    def test_single_request_always_allowed(self, engine):
        """First request in any chain should always pass."""
        d = engine.evaluate("agent1", "read", "calendar_event", "google")
        assert d.allowed is True

    def test_normal_read_create_same_provider_allowed(self, engine):
        """read → create on same provider is fine (not cross-provider)."""
        engine.record("agent1", "read", "calendar_event", "google")
        d = engine.evaluate("agent1", "create", "calendar_event", "google")
        assert d.allowed is True

    def test_cross_provider_exfiltration_denied(self, engine):
        """read on google → create on slack = cross-provider exfiltration."""
        engine.record("agent1", "read", "calendar_event", "google")
        d = engine.evaluate("agent1", "create", "message", "slack")
        assert d.allowed is False
        assert d.matched_rule is not None
        assert d.matched_rule.name == "cross_provider_exfiltration"

    def test_cross_provider_within_window(self, engine):
        """Cross-provider is only flagged within the time window."""
        engine.record("agent1", "read", "calendar_event", "google")
        # Manually age the step beyond the window
        engine._chains["agent1"][0].timestamp = time.monotonic() - 60
        d = engine.evaluate("agent1", "create", "message", "slack")
        assert d.allowed is True  # Outside window — OK

    def test_rapid_create_spam_denied(self, engine):
        """create × 3 in quick succession = spam pattern."""
        engine.record("agent1", "create", "message", "slack")
        engine.record("agent1", "create", "message", "slack")
        d = engine.evaluate("agent1", "create", "message", "slack")
        assert d.allowed is False
        assert d.matched_rule.name == "rapid_create_spam"

    def test_read_delete_alert_not_deny(self, engine):
        """read → delete triggers alert but does NOT deny."""
        engine.record("agent1", "read", "calendar_event", "google")
        d = engine.evaluate("agent1", "delete", "calendar_event", "google")
        assert d.allowed is True  # Alert only, not deny
        assert len(engine.alerts) == 1
        assert engine.alerts[0]["rule"] == "bulk_delete_after_read"

    def test_different_agents_independent(self, engine):
        """Each agent has its own chain — no cross-contamination."""
        engine.record("agent1", "read", "calendar_event", "google")
        d = engine.evaluate("agent2", "create", "message", "slack")
        assert d.allowed is True  # agent2 has no prior chain

    def test_custom_rule_addition(self, engine):
        """Custom rules can be added at runtime."""
        rule = WorkflowRule(
            name="no_update_after_read",
            description="Test rule",
            sequence=["read", "update"],
            effect="deny",
            reason="Test deny",
            window_seconds=30.0,
        )
        engine.add_rule(rule)
        engine.record("agent1", "read", "calendar_event", "google")
        d = engine.evaluate("agent1", "update", "calendar_event", "google")
        assert d.allowed is False
        assert d.matched_rule.name == "no_update_after_read"

    def test_stats(self, engine):
        engine.record("agent1", "read", "calendar_event", "google")
        stats = engine.stats
        assert stats["rules_count"] == len(DEFAULT_WORKFLOW_RULES)
        assert stats["tracked_agents"] == 1

    def test_history_bounded(self):
        """Per-agent history is bounded to max_history."""
        engine = WorkflowEngine(rules=[], max_history_per_agent=5)
        for i in range(20):
            engine.record("agent1", "read", "calendar_event", "google")
        assert len(engine._chains["agent1"]) == 5


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 2. L3 Escalation Manager
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestL3EscalationManager:
    """Test L3 webhook escalation integration."""

    @pytest.fixture
    def notifier(self):
        n = WebhookNotifier()
        n.notify = AsyncMock()  # Mock webhook delivery
        return n

    @pytest.fixture
    def manager(self, notifier):
        return L3EscalationManager(webhook_notifier=notifier)

    @pytest.mark.asyncio
    async def test_escalation_fires_webhook(self, manager, notifier):
        l2_result = IntentResult("create", "unknown", 0.6, "L1")
        await manager.escalate("POST", "/unknown/path", "google", None, l2_result)
        notifier.notify.assert_called_once()
        call_args = notifier.notify.call_args
        assert call_args[0][0] == "l3_escalation"

    @pytest.mark.asyncio
    async def test_escalation_records_history(self, manager):
        l2_result = IntentResult("delete", "unknown", 0.5, "L1")
        await manager.escalate("DELETE", "/some/path", "microsoft", None, l2_result)
        assert manager.pending_count == 1
        recent = manager.recent_escalations
        assert len(recent) == 1
        assert recent[0]["l2_intent"] == "delete"

    @pytest.mark.asyncio
    async def test_escalation_resolve(self, manager):
        l2_result = IntentResult("create", "unknown", 0.5, "L1")
        await manager.escalate("POST", "/test", "google", None, l2_result)
        assert manager.pending_count == 1
        manager.resolve(0, "Reviewed — false positive")
        assert manager.pending_count == 0

    @pytest.mark.asyncio
    async def test_webhook_failure_non_fatal(self, notifier):
        notifier.notify = AsyncMock(side_effect=RuntimeError("Connection refused"))
        manager = L3EscalationManager(webhook_notifier=notifier)
        l2_result = IntentResult("create", "unknown", 0.5, "L1")
        # Should not raise
        await manager.escalate("POST", "/test", "google", None, l2_result)
        assert manager.pending_count == 1

    @pytest.mark.asyncio
    async def test_l3_callback_integration_with_analyzer(self, manager):
        """Verify IntentAnalyzer fires L3 for low-confidence intents."""
        analyzer = IntentAnalyzer(l3_callback=manager.escalate)
        # Unknown path → low confidence → L3 fires
        result = await analyzer.analyze("POST", "/completely/unknown", "google")
        await asyncio.sleep(0.1)  # Let fire-and-forget complete
        assert result.confidence == 0.6
        assert manager.pending_count == 1

    @pytest.mark.asyncio
    async def test_l3_does_not_fire_for_known_resource(self, manager):
        analyzer = IntentAnalyzer(l3_callback=manager.escalate)
        result = await analyzer.analyze("GET", "/calendars/primary/events", "google")
        await asyncio.sleep(0.1)
        assert result.confidence == 0.95
        assert manager.pending_count == 0

    def test_stats(self, manager):
        stats = manager.stats
        assert stats["total_escalations"] == 0
        assert stats["pending"] == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3. New Provider Policies
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestNewProviderPolicies:
    """Verify all 12 policy YAML files load and evaluate correctly."""

    @pytest.fixture
    def engine(self):
        return PolicyEngine(
            policy_dir=str(Path(__file__).parent.parent / "policies")
        )

    def test_all_policies_loaded(self, engine):
        """All YAML files should load without error."""
        expected = {
            "default", "readwrite",
            "microsoft_readonly", "microsoft_readwrite",
            "slack_readonly",
            "github_readonly", "jira_readonly", "notion_readonly",
            "hubspot_readonly", "salesforce_readonly", "linear_readonly", "aws_readonly",
        }
        loaded = set(engine.policy_names)
        assert expected.issubset(loaded), f"Missing: {expected - loaded}"

    # ── HubSpot ────────────────────────────────────────────
    def test_hubspot_allows_contact_read(self, engine):
        d = engine.evaluate("hubspot_readonly", "GET", "/crm/v3/objects/contacts/123")
        assert d.effect == "allow"

    def test_hubspot_denies_contact_create(self, engine):
        d = engine.evaluate("hubspot_readonly", "POST", "/crm/v3/objects/contacts")
        assert d.effect == "deny"

    def test_hubspot_allows_deal_read(self, engine):
        d = engine.evaluate("hubspot_readonly", "GET", "/crm/v3/objects/deals/456")
        assert d.effect == "allow"

    # ── Salesforce ─────────────────────────────────────────
    def test_salesforce_allows_query(self, engine):
        d = engine.evaluate("salesforce_readonly", "GET", "/query")
        assert d.effect == "allow"

    def test_salesforce_allows_account_read(self, engine):
        d = engine.evaluate("salesforce_readonly", "GET", "/sobjects/Account/001xxx")
        assert d.effect == "allow"

    def test_salesforce_denies_account_delete(self, engine):
        d = engine.evaluate("salesforce_readonly", "DELETE", "/sobjects/Account/001xxx")
        assert d.effect == "deny"

    def test_salesforce_allows_opportunity_read(self, engine):
        d = engine.evaluate("salesforce_readonly", "GET", "/sobjects/Opportunity/006xxx")
        assert d.effect == "allow"

    # ── Linear ─────────────────────────────────────────────
    def test_linear_allows_graphql_read(self, engine):
        intent = IntentResult("read", "graphql", 0.95, "L2")
        d = engine.evaluate("linear_readonly", "POST", "/graphql", intent=intent)
        assert d.effect == "allow"

    def test_linear_denies_graphql_without_read_intent(self, engine):
        intent = IntentResult("create", "graphql", 0.95, "L2")
        d = engine.evaluate("linear_readonly", "POST", "/graphql", intent=intent)
        assert d.effect == "deny"

    def test_linear_allows_issue_read(self, engine):
        d = engine.evaluate("linear_readonly", "GET", "/issues/abc")
        assert d.effect == "allow"

    # ── AWS ────────────────────────────────────────────────
    def test_aws_allows_lambda_describe(self, engine):
        d = engine.evaluate("aws_readonly", "GET", "/lambda/functions/my-func")
        assert d.effect == "allow"

    def test_aws_denies_lambda_invoke(self, engine):
        d = engine.evaluate("aws_readonly", "POST", "/lambda/functions/my-func/invocations")
        assert d.effect == "deny"

    def test_aws_allows_s3_read(self, engine):
        d = engine.evaluate("aws_readonly", "GET", "/s3/my-bucket/key.json")
        assert d.effect == "allow"

    def test_aws_denies_s3_delete(self, engine):
        d = engine.evaluate("aws_readonly", "DELETE", "/s3/my-bucket/key.json")
        assert d.effect == "deny"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 4. E2E API Endpoint Tests (Analytics + Policy Builder + L3 + Workflow)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestAPIEndpoints:
    """Test new API endpoints via FastAPI TestClient."""

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from app.main import app
        return TestClient(app)

    @pytest.fixture
    def headers(self):
        from app.config import settings
        return {"X-Master-Key": settings.master_api_key}

    # ── Analytics ──────────────────────────────────────────
    def test_analytics_timeseries(self, client, headers):
        r = client.get("/analytics/timeseries?hours=1", headers=headers)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_analytics_deny_trends(self, client, headers):
        r = client.get("/analytics/deny-trends?hours=1", headers=headers)
        assert r.status_code == 200
        data = r.json()
        assert "top_deny_reasons" in data
        assert "deny_rate_series" in data

    def test_analytics_heatmap(self, client, headers):
        r = client.get("/analytics/heatmap?hours=1", headers=headers)
        assert r.status_code == 200

    def test_analytics_anomalies(self, client, headers):
        r = client.get("/analytics/anomalies?window_minutes=5", headers=headers)
        assert r.status_code == 200

    def test_analytics_latency(self, client, headers):
        r = client.get("/analytics/latency?hours=1", headers=headers)
        assert r.status_code == 200
        data = r.json()
        assert "p50" in data
        assert "p99" in data

    def test_analytics_intents(self, client, headers):
        r = client.get("/analytics/intents?hours=1", headers=headers)
        assert r.status_code == 200

    def test_analytics_requires_master_key(self, client):
        r = client.get("/analytics/timeseries")
        assert r.status_code == 403

    # ── Policy Builder ─────────────────────────────────────
    def test_policy_build(self, client, headers):
        r = client.post("/policies/build", headers=headers, json={
            "name": "test_nl",
            "description": "NL test",
            "provider": "google",
            "rules": ["agents can read events", "agents cannot delete events"],
        })
        assert r.status_code == 200
        data = r.json()
        assert "yaml" in data
        assert len(data["parsed_rules"]) == 2
        assert data["parsed_rules"][0]["effect"] == "allow"
        assert data["parsed_rules"][1]["effect"] == "deny"

    def test_policy_build_with_warnings(self, client, headers):
        r = client.post("/policies/build", headers=headers, json={
            "name": "warn_test",
            "provider": "google",
            "rules": ["xyzzy foobar baz"],
        })
        assert r.status_code == 200
        assert len(r.json()["warnings"]) > 0

    # ── L3 Escalation ──────────────────────────────────────
    def test_l3_escalations_list(self, client, headers):
        r = client.get("/l3/escalations", headers=headers)
        assert r.status_code == 200
        data = r.json()
        assert "escalations" in data
        assert "stats" in data

    # ── Workflow ───────────────────────────────────────────
    def test_workflow_rules_list(self, client, headers):
        r = client.get("/workflow/rules", headers=headers)
        assert r.status_code == 200
        data = r.json()
        assert "rules_count" in data
        assert data["rules_count"] >= len(DEFAULT_WORKFLOW_RULES)

    def test_workflow_add_rule(self, client, headers):
        r = client.post("/workflow/rules", headers=headers, json={
            "name": "test_rule",
            "description": "Test workflow rule",
            "sequence": ["read", "delete"],
            "effect": "deny",
            "reason": "Test deny",
            "window_seconds": 30,
        })
        assert r.status_code == 200
        assert r.json()["status"] == "added"

    def test_workflow_alerts(self, client, headers):
        r = client.get("/workflow/alerts", headers=headers)
        assert r.status_code == 200
        assert "alerts" in r.json()

    # ── Providers ──────────────────────────────────────────
    def test_providers_list_has_10(self, client):
        r = client.get("/providers")
        assert r.status_code == 200
        providers = r.json()["providers"]
        assert len(providers) >= 10

    # ── Health ─────────────────────────────────────────────
    def test_health_shows_version(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["version"] == "0.3.0"
