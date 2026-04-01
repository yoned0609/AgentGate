"""Tests for MarketDisruptor countermeasures:
1. L3 async escalation in IntentAnalyzer
2. 10 providers with L2 patterns
3. Analytics engine
4. Natural language policy builder
"""

from __future__ import annotations

import asyncio
import pytest

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.intent import IntentAnalyzer, IntentResult
from app.connectors import available_providers, get_connector
from app.policy import PolicyEngine
from app.policy_builder import PolicyBuildRequest, build_policy
from app.analytics import AnalyticsEngine


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 1. Provider Coverage — 10 Providers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestProviderCoverage:
    """Verify 10+ providers are registered and functional."""

    def test_ten_providers_registered(self):
        providers = available_providers()
        assert len(providers) >= 10
        expected = {"google", "microsoft", "slack", "github", "jira",
                    "notion", "linear", "hubspot", "salesforce", "aws"}
        assert expected.issubset(set(providers))

    @pytest.mark.parametrize("provider", [
        "google", "microsoft", "slack", "github", "jira",
        "notion", "linear", "hubspot", "salesforce", "aws",
    ])
    def test_connector_instantiation(self, provider):
        connector = get_connector(provider)
        assert connector is not None
        assert connector.name == provider
        assert connector.base_url.startswith("https://")

    @pytest.mark.parametrize("provider", [
        "google", "microsoft", "slack", "github", "jira",
        "notion", "linear", "hubspot", "salesforce", "aws",
    ])
    def test_connector_builds_target_url(self, provider):
        connector = get_connector(provider)
        url = connector.build_target_url("/test/path", "key=value")
        assert "/test/path" in url
        assert "key=value" in url


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 2. L2 Intent Patterns — New Providers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestNewProviderIntents:
    """Verify L2 intent classification for all 10 providers."""

    @pytest.fixture
    def analyzer(self):
        return IntentAnalyzer()

    # ── GitHub ─────────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_github_issue_read(self, analyzer):
        r = await analyzer.analyze("GET", "/repos/org/repo/issues/42", "github")
        assert r.intent_type == "read"
        assert r.resource_type == "issue"
        assert r.analysis_level == "L2"

    @pytest.mark.asyncio
    async def test_github_pr_create(self, analyzer):
        r = await analyzer.analyze("POST", "/repos/org/repo/pulls", "github")
        assert r.intent_type == "create"
        assert r.resource_type == "pull_request"

    @pytest.mark.asyncio
    async def test_github_contents_read(self, analyzer):
        r = await analyzer.analyze("GET", "/repos/org/repo/contents/src/main.py", "github")
        assert r.intent_type == "read"
        assert r.resource_type == "repository_content"

    @pytest.mark.asyncio
    async def test_github_workflow_read(self, analyzer):
        r = await analyzer.analyze("GET", "/repos/org/repo/actions/runs", "github")
        assert r.intent_type == "read"
        assert r.resource_type == "workflow_run"

    # ── Jira ───────────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_jira_issue_read(self, analyzer):
        r = await analyzer.analyze("GET", "/issue/PROJ-123", "jira")
        assert r.intent_type == "read"
        assert r.resource_type == "issue"

    @pytest.mark.asyncio
    async def test_jira_search_post_is_read(self, analyzer):
        r = await analyzer.analyze("POST", "/search", "jira")
        assert r.intent_type == "read"
        assert r.resource_type == "search"

    @pytest.mark.asyncio
    async def test_jira_comment_create(self, analyzer):
        r = await analyzer.analyze("POST", "/issue/PROJ-123/comment", "jira")
        assert r.intent_type == "create"
        assert r.resource_type == "issue_comment"

    @pytest.mark.asyncio
    async def test_jira_transition(self, analyzer):
        r = await analyzer.analyze("POST", "/issue/PROJ-123/transitions", "jira")
        assert r.intent_type == "create"
        assert r.resource_type == "issue_transition"

    # ── Notion ─────────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_notion_page_read(self, analyzer):
        r = await analyzer.analyze("GET", "/pages/abc123", "notion")
        assert r.intent_type == "read"
        assert r.resource_type == "page"

    @pytest.mark.asyncio
    async def test_notion_database_query_is_read(self, analyzer):
        r = await analyzer.analyze("POST", "/databases/abc/query", "notion")
        assert r.intent_type == "read"

    @pytest.mark.asyncio
    async def test_notion_search_post_is_read(self, analyzer):
        r = await analyzer.analyze("POST", "/search", "notion")
        assert r.intent_type == "read"

    @pytest.mark.asyncio
    async def test_notion_page_create(self, analyzer):
        r = await analyzer.analyze("POST", "/pages", "notion")
        assert r.intent_type == "create"
        assert r.resource_type == "page"

    # ── Linear ─────────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_linear_graphql_is_read(self, analyzer):
        r = await analyzer.analyze("POST", "/graphql", "linear")
        assert r.intent_type == "read"
        assert r.resource_type == "graphql"

    # ── HubSpot ────────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_hubspot_contact_read(self, analyzer):
        r = await analyzer.analyze("GET", "/crm/v3/objects/contacts/123", "hubspot")
        assert r.intent_type == "read"
        assert r.resource_type == "contact"

    @pytest.mark.asyncio
    async def test_hubspot_deal_create(self, analyzer):
        r = await analyzer.analyze("POST", "/crm/v3/objects/deals", "hubspot")
        assert r.intent_type == "create"
        assert r.resource_type == "deal"

    # ── Salesforce ─────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_salesforce_account_read(self, analyzer):
        r = await analyzer.analyze("GET", "/sobjects/Account/001xxx", "salesforce")
        assert r.intent_type == "read"
        assert r.resource_type == "account"

    @pytest.mark.asyncio
    async def test_salesforce_opportunity_delete(self, analyzer):
        r = await analyzer.analyze("DELETE", "/sobjects/Opportunity/006xxx", "salesforce")
        assert r.intent_type == "delete"
        assert r.resource_type == "opportunity"

    @pytest.mark.asyncio
    async def test_salesforce_soql_query(self, analyzer):
        r = await analyzer.analyze("GET", "/query", "salesforce")
        assert r.intent_type == "read"
        assert r.resource_type == "soql_query"

    # ── AWS ────────────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_aws_lambda_invoke(self, analyzer):
        r = await analyzer.analyze("POST", "/lambda/functions/my-func/invocations", "aws")
        assert r.intent_type == "create"
        assert r.resource_type == "lambda_invocation"

    @pytest.mark.asyncio
    async def test_aws_s3_read(self, analyzer):
        r = await analyzer.analyze("GET", "/s3/my-bucket/my-key.json", "aws")
        assert r.intent_type == "read"
        assert r.resource_type == "s3_object"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3. L3 Async Escalation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestL3Escalation:
    """Verify L3 async callback fires for low-confidence cases."""

    @pytest.mark.asyncio
    async def test_l3_fires_for_unknown_resource(self):
        escalations = []

        async def l3_callback(method, path, provider, body, result):
            escalations.append({"method": method, "path": path, "result": result})

        analyzer = IntentAnalyzer(l3_callback=l3_callback)
        result = await analyzer.analyze("POST", "/unknown/endpoint", "google")

        # L3 fires asynchronously — give it a moment
        await asyncio.sleep(0.1)

        assert result.intent_type == "create"  # L1 still works
        assert result.confidence == 0.6        # Low confidence triggers L3
        assert len(escalations) == 1
        assert escalations[0]["path"] == "/unknown/endpoint"

    @pytest.mark.asyncio
    async def test_l3_does_not_fire_for_high_confidence(self):
        escalations = []

        async def l3_callback(method, path, provider, body, result):
            escalations.append(result)

        analyzer = IntentAnalyzer(l3_callback=l3_callback)
        result = await analyzer.analyze("GET", "/calendars/primary/events", "google")

        await asyncio.sleep(0.1)

        assert result.confidence == 0.95
        assert len(escalations) == 0  # L3 NOT triggered

    @pytest.mark.asyncio
    async def test_l3_callback_failure_does_not_break_l2(self):
        async def failing_callback(method, path, provider, body, result):
            raise RuntimeError("LLM service down")

        analyzer = IntentAnalyzer(l3_callback=failing_callback)
        # Should still return L1/L2 result without error
        result = await analyzer.analyze("POST", "/unknown/path", "google")
        await asyncio.sleep(0.1)
        assert result.intent_type == "create"

    @pytest.mark.asyncio
    async def test_l3_not_configured_still_works(self):
        analyzer = IntentAnalyzer()  # No callback
        result = await analyzer.analyze("GET", "/repos/org/repo/issues", "github")
        assert result.resource_type == "issue"
        assert result.analysis_level == "L2"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 4. New Provider Policies
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestNewProviderPolicies:
    """Verify new YAML policies load and evaluate correctly."""

    @pytest.fixture
    def engine(self):
        return PolicyEngine(
            policy_dir=str(Path(__file__).parent.parent / "policies")
        )

    def test_github_policy_loads(self, engine):
        policy = engine.get_policy("github_readonly")
        assert policy is not None
        assert len(policy.rules) > 0

    def test_github_policy_allows_read(self, engine):
        intent = IntentResult(
            intent_type="read", resource_type="issue",
            confidence=0.95, analysis_level="L2",
        )
        decision = engine.evaluate("github_readonly", "GET", "/repos/org/repo/issues", intent=intent)
        assert decision.effect == "allow"

    def test_github_policy_denies_write(self, engine):
        intent = IntentResult(
            intent_type="create", resource_type="issue",
            confidence=0.95, analysis_level="L2",
        )
        decision = engine.evaluate("github_readonly", "POST", "/repos/org/repo/issues", intent=intent)
        assert decision.effect == "deny"

    def test_jira_policy_loads(self, engine):
        policy = engine.get_policy("jira_readonly")
        assert policy is not None

    def test_jira_policy_allows_issue_read(self, engine):
        decision = engine.evaluate("jira_readonly", "GET", "/issue/PROJ-123")
        assert decision.effect == "allow"

    def test_jira_policy_denies_issue_create(self, engine):
        decision = engine.evaluate("jira_readonly", "POST", "/issue")
        assert decision.effect == "deny"

    def test_notion_policy_loads(self, engine):
        policy = engine.get_policy("notion_readonly")
        assert policy is not None

    def test_notion_policy_allows_page_read(self, engine):
        decision = engine.evaluate("notion_readonly", "GET", "/pages/abc123")
        assert decision.effect == "allow"

    def test_notion_policy_allows_search(self, engine):
        intent = IntentResult(
            intent_type="read", resource_type="search",
            confidence=0.95, analysis_level="L2",
        )
        decision = engine.evaluate("notion_readonly", "POST", "/search", intent=intent)
        assert decision.effect == "allow"

    def test_notion_policy_denies_page_delete(self, engine):
        decision = engine.evaluate("notion_readonly", "DELETE", "/pages/abc123")
        assert decision.effect == "deny"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 5. Natural Language Policy Builder
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestPolicyBuilder:
    """Test natural language → YAML policy generation."""

    def test_simple_read_allow(self):
        req = PolicyBuildRequest(
            name="test_policy",
            description="Test",
            provider="google",
            rules_nl=["agents can read events"],
        )
        result = build_policy(req)
        assert len(result.parsed_rules) == 1
        assert result.parsed_rules[0]["effect"] == "allow"
        assert "read" in str(result.parsed_rules[0].get("intent", ""))
        assert result.parsed_rules[0]["resource"] == "/calendars/*/events"

    def test_deny_delete(self):
        req = PolicyBuildRequest(
            name="test_deny",
            description="Test",
            provider="google",
            rules_nl=["agents cannot delete events"],
        )
        result = build_policy(req)
        assert len(result.parsed_rules) == 1
        assert result.parsed_rules[0]["effect"] == "deny"
        assert "delete" in str(result.parsed_rules[0].get("intent", ""))

    def test_multiple_rules(self):
        req = PolicyBuildRequest(
            name="multi",
            description="Multiple rules",
            provider="github",
            rules_nl=[
                "agents can read issues",
                "agents can read pull requests",
                "agents cannot delete repository",
            ],
        )
        result = build_policy(req)
        assert len(result.parsed_rules) == 3
        assert result.parsed_rules[0]["effect"] == "allow"
        assert result.parsed_rules[2]["effect"] == "deny"

    def test_github_rules(self):
        req = PolicyBuildRequest(
            name="github_custom",
            description="Custom GitHub policy",
            provider="github",
            rules_nl=["agents can read issues and pull requests"],
        )
        result = build_policy(req)
        assert len(result.parsed_rules) == 1
        rule = result.parsed_rules[0]
        assert "GET" in rule.get("methods", [])

    def test_jira_rules(self):
        req = PolicyBuildRequest(
            name="jira_custom",
            description="Custom Jira policy",
            provider="jira",
            rules_nl=["agents can read issues but cannot create issues"],
        )
        result = build_policy(req)
        # "read" and "create" both detected → allow with both intents, but "cannot" → deny
        assert len(result.parsed_rules) == 1

    def test_yaml_output_valid(self):
        import yaml
        req = PolicyBuildRequest(
            name="yaml_test",
            description="YAML validation test",
            provider="notion",
            rules_nl=["agents can read pages", "agents cannot delete databases"],
        )
        result = build_policy(req)
        # Verify YAML parses correctly
        data = yaml.safe_load(result.yaml_content)
        assert data["name"] == "yaml_test"
        assert len(data["rules"]) == 2

    def test_unparseable_rule_generates_warning(self):
        req = PolicyBuildRequest(
            name="warn_test",
            description="Warning test",
            provider="google",
            rules_nl=["xyzzy foobar baz"],
        )
        result = build_policy(req)
        assert len(result.warnings) > 0

    def test_hubspot_rules(self):
        req = PolicyBuildRequest(
            name="hubspot_readonly",
            description="HubSpot read-only",
            provider="hubspot",
            rules_nl=["agents can read contacts and companies"],
        )
        result = build_policy(req)
        assert len(result.parsed_rules) == 1
        assert result.parsed_rules[0]["effect"] == "allow"

    def test_rate_limit_in_yaml(self):
        import yaml
        req = PolicyBuildRequest(
            name="rate_test",
            description="Rate limit test",
            provider="google",
            rules_nl=["agents can read events"],
            rate_limit_per_minute=30,
            rate_limit_per_hour=500,
        )
        result = build_policy(req)
        data = yaml.safe_load(result.yaml_content)
        assert data["rate_limit"]["requests_per_minute"] == 30
        assert data["rate_limit"]["requests_per_hour"] == 500


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 6. Analytics Engine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestAnalyticsEngine:
    """Test analytics queries against a seeded audit DB."""

    @pytest.fixture
    def seeded_engine(self, tmp_path):
        """Create an analytics engine with seeded test data."""
        import sqlite3
        db_path = str(tmp_path / "test_audit.db")
        conn = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                agent_id TEXT NOT NULL,
                agent_name TEXT NOT NULL DEFAULT '',
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                provider TEXT NOT NULL DEFAULT '',
                decision TEXT NOT NULL,
                deny_reason TEXT,
                intent TEXT DEFAULT '',
                intent_confidence REAL DEFAULT 0,
                status_code INTEGER,
                latency_ms REAL NOT NULL DEFAULT 0,
                request_id TEXT NOT NULL
            );
        """)
        # Seed test data
        for i in range(50):
            decision = "allow" if i % 3 != 0 else "deny"
            provider = ["google", "github", "slack"][i % 3]
            intent = ["read", "create", "delete"][i % 3]
            conn.execute(
                """INSERT INTO audit_logs
                   (agent_id, agent_name, method, path, provider, decision,
                    deny_reason, intent, intent_confidence, status_code,
                    latency_ms, request_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    f"agent_{i % 3}",
                    f"test_agent_{i % 3}",
                    "GET" if decision == "allow" else "DELETE",
                    f"/test/path/{i}",
                    provider,
                    decision,
                    "denied by policy" if decision == "deny" else None,
                    intent,
                    0.95,
                    200 if decision == "allow" else 403,
                    1.5 + (i * 0.1),
                    f"req_{i:04d}",
                ),
            )
        conn.commit()
        conn.close()
        return AnalyticsEngine(db_path=db_path)

    @pytest.mark.asyncio
    async def test_time_series(self, seeded_engine):
        result = await seeded_engine.time_series(interval="hour", hours=1)
        assert isinstance(result, list)
        if result:
            assert "bucket" in result[0]
            assert "total" in result[0]
            assert "allowed" in result[0]
            assert "denied" in result[0]

    @pytest.mark.asyncio
    async def test_deny_trends(self, seeded_engine):
        result = await seeded_engine.deny_trends(hours=1)
        assert "top_deny_reasons" in result
        assert "deny_rate_series" in result

    @pytest.mark.asyncio
    async def test_agent_heatmap(self, seeded_engine):
        result = await seeded_engine.agent_heatmap(hours=1)
        assert isinstance(result, list)
        if result:
            assert "agent_name" in result[0]
            assert "provider" in result[0]
            assert "cnt" in result[0]

    @pytest.mark.asyncio
    async def test_anomaly_detection(self, seeded_engine):
        result = await seeded_engine.anomaly_detection(window_minutes=60)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_latency_percentiles(self, seeded_engine):
        result = await seeded_engine.latency_percentiles(hours=1)
        assert "p50" in result
        assert "p90" in result
        assert "p95" in result
        assert "p99" in result
        assert result["count"] == 50

    @pytest.mark.asyncio
    async def test_intent_distribution(self, seeded_engine):
        result = await seeded_engine.intent_distribution(hours=1)
        assert isinstance(result, list)
        if result:
            assert "intent" in result[0]
            assert "decision" in result[0]
            assert "cnt" in result[0]

    @pytest.mark.asyncio
    async def test_time_series_with_filters(self, seeded_engine):
        result = await seeded_engine.time_series(
            interval="minute", agent_id="agent_0", hours=1
        )
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_latency_empty_db(self, tmp_path):
        import sqlite3
        db_path = str(tmp_path / "empty.db")
        conn = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                agent_id TEXT NOT NULL,
                agent_name TEXT NOT NULL DEFAULT '',
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                provider TEXT NOT NULL DEFAULT '',
                decision TEXT NOT NULL,
                deny_reason TEXT,
                intent TEXT DEFAULT '',
                intent_confidence REAL DEFAULT 0,
                status_code INTEGER,
                latency_ms REAL NOT NULL DEFAULT 0,
                request_id TEXT NOT NULL
            );
        """)
        conn.close()
        engine = AnalyticsEngine(db_path=db_path)
        result = await engine.latency_percentiles(hours=1)
        assert result["count"] == 0
