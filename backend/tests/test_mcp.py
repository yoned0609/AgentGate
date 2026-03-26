"""Tests for MCP Auth Proxy — annotation conversion, policy evaluation, and JSON-RPC handling."""

from unittest.mock import AsyncMock, patch

import pytest

from app.mcp.annotations import (
    classify_tool_intent,
    tool_to_policy_rules,
    tools_to_policy,
)
from app.mcp.proxy import MCPAuthProxy
from app.audit import AuditLogger
from app.policy import PolicyEngine


# ── Annotation conversion tests ─────────────────────────────────────


class TestAnnotationConversion:
    def test_destructive_tool_generates_deny_rule(self):
        tool = {
            "name": "delete_file",
            "annotations": {"destructiveHint": True},
        }
        rules = tool_to_policy_rules(tool)
        deny_rules = [r for r in rules if r["effect"] == "deny"]
        assert len(deny_rules) == 1
        assert deny_rules[0]["intent"] == "delete"
        assert "/mcp/tools/delete_file" in deny_rules[0]["resource"]

    def test_readonly_tool_generates_allow_rule(self):
        tool = {
            "name": "list_files",
            "annotations": {"readOnlyHint": True},
        }
        rules = tool_to_policy_rules(tool)
        allow_rules = [r for r in rules if r["effect"] == "allow"]
        assert len(allow_rules) == 1
        assert allow_rules[0]["intent"] == "read"

    def test_no_annotations_generates_default_allow(self):
        tool = {"name": "unknown_tool"}
        rules = tool_to_policy_rules(tool)
        assert len(rules) == 1
        assert rules[0]["effect"] == "allow"

    def test_tools_to_policy_creates_valid_policy(self):
        tools = [
            {"name": "read_cal", "annotations": {"readOnlyHint": True}},
            {"name": "delete_cal", "annotations": {"destructiveHint": True}},
        ]
        policy = tools_to_policy(tools, policy_name="test_mcp")
        assert policy["name"] == "test_mcp"
        assert len(policy["rules"]) >= 2
        assert policy["default_effect"] == "deny"


class TestClassifyToolIntent:
    def test_destructive(self):
        assert classify_tool_intent("x", {"destructiveHint": True}) == "delete"

    def test_readonly(self):
        assert classify_tool_intent("x", {"readOnlyHint": True}) == "read"

    def test_idempotent(self):
        assert classify_tool_intent("x", {"idempotentHint": True}) == "update"

    def test_openworld(self):
        assert classify_tool_intent("x", {"openWorldHint": True}) == "query"

    def test_no_annotations(self):
        assert classify_tool_intent("x", {}) == "unknown"


# ── MCP Proxy tests ─────────────────────────────────────────────────


class TestMCPAuthProxy:
    @pytest.fixture
    def policy_engine(self, tmp_path):
        """Create a policy engine with an MCP policy."""
        import yaml

        policy = {
            "name": "mcp_test",
            "rules": [
                {
                    "resource": "/mcp/tools/read_data",
                    "methods": ["POST"],
                    "intent": "read",
                    "effect": "allow",
                },
                {
                    "resource": "/mcp/tools/delete_data",
                    "methods": ["POST"],
                    "intent": "delete",
                    "effect": "deny",
                    "reason": "Destructive MCP tools are not allowed",
                },
            ],
            "default_effect": "deny",
            "default_reason": "MCP tool not in allowlist",
        }
        (tmp_path / "mcp_test.yaml").write_text(yaml.dump(policy))
        return PolicyEngine(policy_dir=str(tmp_path))

    @pytest.fixture
    def audit_logger(self, tmp_path):
        return AuditLogger(db_path=str(tmp_path / "test_audit.db"))

    @pytest.fixture
    def mcp_proxy(self, policy_engine, audit_logger):
        proxy = MCPAuthProxy(
            upstream_url="http://localhost:9999/mcp",
            policy_engine=policy_engine,
            audit_logger=audit_logger,
            tool_annotations={
                "read_data": {"readOnlyHint": True},
                "delete_data": {"destructiveHint": True},
            },
        )
        return proxy

    @pytest.mark.asyncio
    async def test_readonly_tool_allowed(self, mcp_proxy):
        """Read-only tool call should be forwarded to upstream."""
        upstream_response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": "data"}]},
        }
        with patch.object(mcp_proxy, "_client") as mock_client:
            import httpx as _httpx

            mock_resp = _httpx.Response(200, json=upstream_response)
            mock_client.post = AsyncMock(return_value=mock_resp)

            result = await mcp_proxy.handle_jsonrpc(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "read_data", "arguments": {}},
                },
                agent_id="agent-1",
                agent_name="test-agent",
                policy_name="mcp_test",
            )

        assert "result" in result
        assert result["result"]["content"][0]["text"] == "data"

    @pytest.mark.asyncio
    async def test_destructive_tool_denied(self, mcp_proxy):
        """Destructive tool call should be denied without forwarding."""
        result = await mcp_proxy.handle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "delete_data", "arguments": {"id": "123"}},
            },
            agent_id="agent-1",
            agent_name="test-agent",
            policy_name="mcp_test",
        )

        assert "error" in result
        assert result["error"]["code"] == -32600
        assert "Access denied" in result["error"]["message"]
        assert result["error"]["data"]["tool"] == "delete_data"
        assert result["error"]["data"]["intent"] == "delete"

    @pytest.mark.asyncio
    async def test_non_tool_method_forwarded(self, mcp_proxy):
        """Non tools/call methods (e.g., resources/list) should be forwarded."""
        upstream_response = {
            "jsonrpc": "2.0",
            "id": 3,
            "result": {"resources": []},
        }
        with patch.object(mcp_proxy, "_client") as mock_client:
            import httpx as _httpx

            mock_resp = _httpx.Response(200, json=upstream_response)
            mock_client.post = AsyncMock(return_value=mock_resp)

            result = await mcp_proxy.handle_jsonrpc(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "resources/list",
                    "params": {},
                },
                agent_id="agent-1",
                agent_name="test-agent",
                policy_name="mcp_test",
            )

        assert "result" in result

    @pytest.mark.asyncio
    async def test_unknown_tool_denied_by_default(self, mcp_proxy):
        """Tool not in policy should be denied by default_effect."""
        result = await mcp_proxy.handle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "unknown_tool", "arguments": {}},
            },
            agent_id="agent-1",
            agent_name="test-agent",
            policy_name="mcp_test",
        )

        assert "error" in result
        assert "not in allowlist" in result["error"]["data"]["reason"]

    @pytest.mark.asyncio
    async def test_deny_creates_audit_entry(self, mcp_proxy, audit_logger):
        """Denied MCP tool calls should be recorded in audit log."""
        await mcp_proxy.handle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "delete_data", "arguments": {}},
            },
            agent_id="agent-1",
            agent_name="test-agent",
            policy_name="mcp_test",
        )

        logs, total = await audit_logger.query(provider="mcp", decision="deny")
        assert total >= 1
        assert logs[0]["method"] == "MCP:tools/call"
        assert logs[0]["provider"] == "mcp"
