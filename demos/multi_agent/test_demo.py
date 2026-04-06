"""
Multi-Agent Demo — Test Suite
"""

from __future__ import annotations

import pytest
from pathlib import Path

from gate_proxy import AgentGateProxy, PolicyEngine, Decision
from agents import OrchestratorAgent, ExecutorAgent, ReviewerAgent


@pytest.fixture
def policy_engine():
    policy_path = Path(__file__).parent / "policies.yaml"
    return PolicyEngine(policy_path)


@pytest.fixture
def proxy(policy_engine):
    return AgentGateProxy(policy_engine=policy_engine)


@pytest.fixture
def setup_agents(proxy):
    orchestrator = OrchestratorAgent(agent_id="orchestrator", role="orchestrator", proxy=proxy)
    ExecutorAgent(agent_id="executor", role="executor", proxy=proxy)
    ReviewerAgent(agent_id="reviewer", role="reviewer", proxy=proxy)
    return orchestrator


class TestPolicyEngine:
    def test_clean_payload_allowed(self, policy_engine):
        decision, payload, violations = policy_engine.scan_payload("A normal message")
        assert decision == Decision.ALLOW
        assert violations == []

    def test_pii_email_masked(self, policy_engine):
        decision, payload, violations = policy_engine.scan_payload(
            "Contact: user@example.com"
        )
        assert decision == Decision.MASK
        assert "***" in payload
        assert "user@example.com" not in payload

    def test_pii_phone_masked(self, policy_engine):
        decision, payload, violations = policy_engine.scan_payload(
            "Phone: 090-1234-5678"
        )
        assert decision == Decision.MASK
        assert "090-1234-5678" not in payload

    def test_pii_credit_card_masked(self, policy_engine):
        decision, payload, violations = policy_engine.scan_payload(
            "Card: 4111-1111-1111-1111"
        )
        assert decision == Decision.MASK
        assert "4111-1111-1111-1111" not in payload

    def test_forbidden_sql_injection_blocked(self, policy_engine):
        decision, payload, violations = policy_engine.scan_payload(
            "DROP TABLE users;"
        )
        assert decision == Decision.BLOCK

    def test_forbidden_xss_blocked(self, policy_engine):
        decision, payload, violations = policy_engine.scan_payload(
            '<script>alert("xss")</script>'
        )
        assert decision == Decision.BLOCK

    def test_forbidden_dangerous_command_blocked(self, policy_engine):
        decision, payload, violations = policy_engine.scan_payload("run: rm -rf /")
        assert decision == Decision.BLOCK

    def test_forbidden_confidential_key_blocked(self, policy_engine):
        decision, payload, violations = policy_engine.scan_payload(
            "CONFIDENTIAL_KEY_abc123"
        )
        assert decision == Decision.BLOCK

    def test_routing_allowed(self, policy_engine):
        assert policy_engine.check_routing("orchestrator", "executor") is None
        assert policy_engine.check_routing("orchestrator", "reviewer") is None
        assert policy_engine.check_routing("executor", "orchestrator") is None

    def test_routing_denied(self, policy_engine):
        error = policy_engine.check_routing("executor", "reviewer")
        assert error is not None

    def test_unknown_agent_routing(self, policy_engine):
        error = policy_engine.check_routing("unknown_agent", "executor")
        assert error is not None


class TestAgentGateProxy:
    def test_register_agent(self, proxy):
        proxy.register_agent("test_agent", "executor")
        assert "test_agent" in proxy.agents

    def test_relay_clean_message(self, proxy, setup_agents):
        result = proxy.relay("orchestrator", "executor", "test")
        assert result.decision == Decision.ALLOW
        assert result.delivered_payload == "test"

    def test_relay_pii_masked(self, proxy, setup_agents):
        result = proxy.relay(
            "orchestrator", "executor", "email: test@example.com"
        )
        assert result.decision == Decision.MASK
        assert "test@example.com" not in result.delivered_payload
        assert "***" in result.delivered_payload

    def test_relay_forbidden_blocked(self, proxy, setup_agents):
        result = proxy.relay(
            "orchestrator", "executor", "DROP TABLE users"
        )
        assert result.decision == Decision.BLOCK
        assert result.delivered_payload is None

    def test_relay_routing_violation(self, proxy, setup_agents):
        result = proxy.relay("executor", "reviewer", "unauthorized")
        assert result.decision == Decision.BLOCK

    def test_relay_unregistered_agent(self, proxy):
        with pytest.raises(ValueError, match="Unknown"):
            proxy.relay("ghost", "executor", "hello")

    def test_trace_log_recorded(self, proxy, setup_agents):
        proxy.relay("orchestrator", "executor", "msg1")
        proxy.relay("orchestrator", "reviewer", "msg2")
        logs = proxy.get_trace_log()
        assert len(logs) >= 2

    def test_callback_delivery(self, proxy, setup_agents):
        received = []
        proxy.set_callback("executor", lambda f, p, m: received.append(p))
        proxy.relay("orchestrator", "executor", "callback test")
        assert received == ["callback test"]

    def test_blocked_message_not_delivered(self, proxy, setup_agents):
        received = []
        proxy.set_callback("executor", lambda f, p, m: received.append(p))
        proxy.relay("orchestrator", "executor", "DROP TABLE x")
        assert len(received) == 0


class TestMultiAgentFlow:
    def test_full_flow_completes(self, proxy, setup_agents):
        orchestrator = setup_agents
        result = orchestrator.process_user_task("test task")
        assert result["status"] == "completed"
        assert "Execution Result" in result["execution"]
        assert "Review Result" in result["review"]

    def test_full_flow_trace_count(self, proxy, setup_agents):
        orchestrator = setup_agents
        orchestrator.process_user_task("task")
        logs = proxy.get_trace_log()
        assert len(logs) == 4
        assert all(l["decision"] == "ALLOW" for l in logs)
