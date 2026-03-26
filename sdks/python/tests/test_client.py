"""Unit tests for the AgentGate SDK using httpx mock transport."""

from __future__ import annotations

import json

import httpx
import pytest

from agentgate_sdk import (
    Agent,
    AgentGateClient,
    AgentStats,
    AsyncAgentGateClient,
    AuditExport,
    AuditLogList,
    HealthStatus,
    PolicyInfo,
)
from agentgate_sdk.exceptions import (
    AgentGateError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)

# ── Fixtures: mock data ──────────────────────────────────────────────

AGENT_DATA = {
    "agent_id": "ag_123",
    "name": "test-agent",
    "description": "A test agent",
    "api_key": "key_abc",
    "policy": "default",
    "provider": "google",
    "created_at": "2025-01-01T00:00:00Z",
    "request_count": 5,
    "deny_count": 1,
    "last_request_at": "2025-01-02T00:00:00Z",
}

AGENT_STATS_DATA = {
    "agent_id": "ag_123",
    "name": "test-agent",
    "request_count": 5,
    "deny_count": 1,
    "deny_rate": 0.2,
    "last_request_at": "2025-01-02T00:00:00Z",
}

HEALTH_DATA = {
    "status": "ok",
    "version": "0.2.0",
    "providers": ["google", "openai"],
    "policy_loaded": True,
    "agents_count": 3,
    "audit_db": "ok",
}

AUDIT_LOG_ENTRY = {
    "id": 1,
    "timestamp": "2025-01-01T12:00:00Z",
    "agent_id": "ag_123",
    "agent_name": "test-agent",
    "method": "POST",
    "path": "/v1/chat/completions",
    "provider": "openai",
    "decision": "allow",
    "deny_reason": None,
    "intent": "chat",
    "intent_confidence": 0.95,
    "status_code": 200,
    "latency_ms": 123.4,
    "request_id": "req_abc",
}

POLICY_DATA = {"name": "default", "rules": [{"effect": "allow", "path": "/v1/*"}]}


# ── Mock transport ───────────────────────────────────────────────────


def _build_response(
    status_code: int = 200,
    json_body: dict | list | None = None,
    text: str = "",
    content_type: str = "application/json",
) -> httpx.Response:
    if json_body is not None:
        content = json.dumps(json_body).encode()
    else:
        content = text.encode()
    return httpx.Response(
        status_code=status_code,
        content=content,
        headers={"content-type": content_type},
    )


class MockTransport(httpx.BaseTransport):
    """A simple mock transport that dispatches based on method + path."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], httpx.Response] = {}
        self.last_request: httpx.Request | None = None

    def add(
        self,
        method: str,
        path: str,
        *,
        status: int = 200,
        json_body: dict | list | None = None,
        text: str = "",
    ) -> None:
        self.routes[(method.upper(), path)] = _build_response(
            status_code=status, json_body=json_body, text=text
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.last_request = request
        key = (request.method, request.url.raw_path.decode().split("?")[0])
        if key in self.routes:
            return self.routes[key]
        return _build_response(status_code=404, json_body={"detail": "Not found"})


class AsyncMockTransport(httpx.AsyncBaseTransport):
    """Async version of the mock transport."""

    def __init__(self, sync_transport: MockTransport) -> None:
        self._sync = sync_transport

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return self._sync.handle_request(request)


@pytest.fixture
def transport() -> MockTransport:
    return MockTransport()


@pytest.fixture
def async_transport(transport: MockTransport) -> AsyncMockTransport:
    return AsyncMockTransport(transport)


@pytest.fixture
def client(transport: MockTransport) -> AgentGateClient:
    return AgentGateClient(
        base_url="http://test",
        master_key="master_secret",
        agent_key="agent_secret",
        transport=transport,
    )


@pytest.fixture
def async_client(async_transport: AsyncMockTransport) -> AsyncAgentGateClient:
    return AsyncAgentGateClient(
        base_url="http://test",
        master_key="master_secret",
        agent_key="agent_secret",
        transport=async_transport,
    )


# ── Sync: Health & Discovery ─────────────────────────────────────────


class TestHealth:
    def test_health(self, client: AgentGateClient, transport: MockTransport) -> None:
        transport.add("GET", "/health", json_body=HEALTH_DATA)
        result = client.health()
        assert isinstance(result, HealthStatus)
        assert result.status == "ok"
        assert result.version == "0.2.0"
        assert "google" in result.providers

    def test_providers(
        self, client: AgentGateClient, transport: MockTransport
    ) -> None:
        transport.add("GET", "/providers", json_body={"providers": ["google", "openai"]})
        result = client.providers()
        assert result == ["google", "openai"]


# ── Sync: Agent Management ───────────────────────────────────────────


class TestAgents:
    def test_create(self, client: AgentGateClient, transport: MockTransport) -> None:
        transport.add("POST", "/agents", json_body=AGENT_DATA)
        agent = client.agents.create("test-agent", policy="default", provider="google")
        assert isinstance(agent, Agent)
        assert agent.agent_id == "ag_123"
        assert agent.name == "test-agent"
        # Verify headers were sent
        assert transport.last_request is not None
        assert transport.last_request.headers["x-master-key"] == "master_secret"

    def test_list(self, client: AgentGateClient, transport: MockTransport) -> None:
        transport.add("GET", "/agents", json_body=[AGENT_DATA])
        agents = client.agents.list()
        assert len(agents) == 1
        assert agents[0].agent_id == "ag_123"

    def test_delete(self, client: AgentGateClient, transport: MockTransport) -> None:
        transport.add("DELETE", "/agents/ag_123", json_body={"status": "deleted"})
        result = client.agents.delete("ag_123")
        assert result["status"] == "deleted"

    def test_rotate_key(
        self, client: AgentGateClient, transport: MockTransport
    ) -> None:
        rotated = {**AGENT_DATA, "api_key": "key_new"}
        transport.add("POST", "/agents/ag_123/rotate-key", json_body=rotated)
        agent = client.agents.rotate_key("ag_123")
        assert agent.api_key == "key_new"

    def test_stats(self, client: AgentGateClient, transport: MockTransport) -> None:
        transport.add("GET", "/agents/ag_123/stats", json_body=AGENT_STATS_DATA)
        stats = client.agents.stats("ag_123")
        assert isinstance(stats, AgentStats)
        assert stats.deny_rate == 0.2


# ── Sync: Audit ──────────────────────────────────────────────────────


class TestAudit:
    def test_logs(self, client: AgentGateClient, transport: MockTransport) -> None:
        transport.add(
            "GET",
            "/audit/logs",
            json_body={"logs": [AUDIT_LOG_ENTRY], "total": 1},
        )
        result = client.audit.logs(limit=10)
        assert isinstance(result, AuditLogList)
        assert result.total == 1
        assert result.logs[0].decision == "allow"

    def test_stats(self, client: AgentGateClient, transport: MockTransport) -> None:
        stats_data = {"total_requests": 100, "total_denies": 10}
        transport.add("GET", "/audit/stats", json_body=stats_data)
        result = client.audit.stats()
        assert result["total_requests"] == 100

    def test_export_json(
        self, client: AgentGateClient, transport: MockTransport
    ) -> None:
        export_data = {"logs": [{"id": 1}], "count": 1}
        transport.add("GET", "/audit/export", json_body=export_data)
        result = client.audit.export(format="json")
        assert isinstance(result, AuditExport)
        assert result.count == 1

    def test_export_csv(
        self, client: AgentGateClient, transport: MockTransport
    ) -> None:
        transport.add("GET", "/audit/export", text="id,timestamp\n1,2025-01-01")
        result = client.audit.export(format="csv")
        assert isinstance(result, httpx.Response)

    def test_purge(self, client: AgentGateClient, transport: MockTransport) -> None:
        transport.add(
            "POST",
            "/audit/purge",
            json_body={"purged": 42, "retention_days": 30},
        )
        result = client.audit.purge(retention_days=30)
        assert result.purged == 42


# ── Sync: Proxy ──────────────────────────────────────────────────────


class TestProxy:
    def test_request(self, client: AgentGateClient, transport: MockTransport) -> None:
        transport.add(
            "POST",
            "/proxy/openai/v1/chat/completions",
            json_body={"choices": [{"message": {"content": "hello"}}]},
        )
        resp = client.proxy.request(
            "openai",
            "v1/chat/completions",
            json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
        )
        assert resp.status_code == 200
        assert transport.last_request is not None
        assert transport.last_request.headers["x-agent-key"] == "agent_secret"

    def test_mcp(self, client: AgentGateClient, transport: MockTransport) -> None:
        transport.add(
            "POST",
            "/mcp/my-server",
            json_body={"jsonrpc": "2.0", "result": {"ok": True}, "id": 1},
        )
        result = client.proxy.mcp(
            "my-server",
            jsonrpc_body={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        )
        assert result["result"]["ok"] is True


# ── Sync: Config ─────────────────────────────────────────────────────


class TestConfig:
    def test_list_policies(
        self, client: AgentGateClient, transport: MockTransport
    ) -> None:
        transport.add("GET", "/policies", json_body=[POLICY_DATA])
        policies = client.config.list_policies()
        assert len(policies) == 1
        assert isinstance(policies[0], PolicyInfo)
        assert policies[0].name == "default"

    def test_register_webhook(
        self, client: AgentGateClient, transport: MockTransport
    ) -> None:
        transport.add(
            "POST",
            "/webhooks",
            json_body={
                "status": "registered",
                "url": "https://example.com/hook",
                "events": ["deny"],
            },
        )
        result = client.config.register_webhook(
            "https://example.com/hook", events=["deny"]
        )
        assert result["status"] == "registered"

    def test_register_alert_threshold(
        self, client: AgentGateClient, transport: MockTransport
    ) -> None:
        transport.add(
            "POST",
            "/alerts/thresholds",
            json_body={
                "status": "registered",
                "event": "deny",
                "count": 5,
                "window_seconds": 60,
            },
        )
        result = client.config.register_alert_threshold(count=5, window_seconds=60)
        assert result["status"] == "registered"

    def test_register_mcp_server(
        self, client: AgentGateClient, transport: MockTransport
    ) -> None:
        transport.add(
            "POST",
            "/mcp/servers",
            json_body={
                "status": "registered",
                "name": "fs",
                "url": "http://localhost:3000",
                "tools_registered": 0,
                "auto_policy": None,
            },
        )
        result = client.config.register_mcp_server(
            "http://localhost:3000", name="fs"
        )
        assert result["name"] == "fs"


# ── Exception Mapping ────────────────────────────────────────────────


class TestExceptions:
    @pytest.mark.parametrize(
        "status,exc_cls",
        [
            (401, AuthenticationError),
            (403, AuthorizationError),
            (404, NotFoundError),
            (422, ValidationError),
            (429, RateLimitError),
            (500, ServerError),
            (502, ServerError),
            (418, AgentGateError),  # unmapped 4xx falls back to base
        ],
    )
    def test_status_code_mapping(
        self,
        status: int,
        exc_cls: type,
        transport: MockTransport,
    ) -> None:
        transport.add("GET", "/health", status=status, json_body={"detail": "oops"})
        client = AgentGateClient(base_url="http://test", transport=transport)
        with pytest.raises(exc_cls) as exc_info:
            client.health()
        assert exc_info.value.status_code == status
        assert exc_info.value.response_body == {"detail": "oops"}

    def test_exception_message(self, transport: MockTransport) -> None:
        transport.add(
            "GET", "/health", status=403, json_body={"detail": "Invalid master key"}
        )
        client = AgentGateClient(base_url="http://test", transport=transport)
        with pytest.raises(AuthorizationError, match="Invalid master key"):
            client.health()


# ── Async Tests ──────────────────────────────────────────────────────


class TestAsync:
    async def test_health(
        self,
        async_client: AsyncAgentGateClient,
        transport: MockTransport,
    ) -> None:
        transport.add("GET", "/health", json_body=HEALTH_DATA)
        result = await async_client.health()
        assert isinstance(result, HealthStatus)
        assert result.status == "ok"

    async def test_providers(
        self,
        async_client: AsyncAgentGateClient,
        transport: MockTransport,
    ) -> None:
        transport.add(
            "GET", "/providers", json_body={"providers": ["google"]}
        )
        result = await async_client.providers()
        assert result == ["google"]

    async def test_agents_create(
        self,
        async_client: AsyncAgentGateClient,
        transport: MockTransport,
    ) -> None:
        transport.add("POST", "/agents", json_body=AGENT_DATA)
        agent = await async_client.agents.create("test-agent")
        assert agent.agent_id == "ag_123"

    async def test_agents_list(
        self,
        async_client: AsyncAgentGateClient,
        transport: MockTransport,
    ) -> None:
        transport.add("GET", "/agents", json_body=[AGENT_DATA])
        agents = await async_client.agents.list()
        assert len(agents) == 1

    async def test_agents_delete(
        self,
        async_client: AsyncAgentGateClient,
        transport: MockTransport,
    ) -> None:
        transport.add("DELETE", "/agents/ag_123", json_body={"status": "deleted"})
        result = await async_client.agents.delete("ag_123")
        assert result["status"] == "deleted"

    async def test_agents_rotate_key(
        self,
        async_client: AsyncAgentGateClient,
        transport: MockTransport,
    ) -> None:
        rotated = {**AGENT_DATA, "api_key": "key_new"}
        transport.add("POST", "/agents/ag_123/rotate-key", json_body=rotated)
        agent = await async_client.agents.rotate_key("ag_123")
        assert agent.api_key == "key_new"

    async def test_agents_stats(
        self,
        async_client: AsyncAgentGateClient,
        transport: MockTransport,
    ) -> None:
        transport.add("GET", "/agents/ag_123/stats", json_body=AGENT_STATS_DATA)
        stats = await async_client.agents.stats("ag_123")
        assert stats.deny_rate == 0.2

    async def test_audit_logs(
        self,
        async_client: AsyncAgentGateClient,
        transport: MockTransport,
    ) -> None:
        transport.add(
            "GET",
            "/audit/logs",
            json_body={"logs": [AUDIT_LOG_ENTRY], "total": 1},
        )
        result = await async_client.audit.logs()
        assert result.total == 1

    async def test_audit_purge(
        self,
        async_client: AsyncAgentGateClient,
        transport: MockTransport,
    ) -> None:
        transport.add(
            "POST",
            "/audit/purge",
            json_body={"purged": 10, "retention_days": 90},
        )
        result = await async_client.audit.purge()
        assert result.purged == 10

    async def test_proxy_request(
        self,
        async_client: AsyncAgentGateClient,
        transport: MockTransport,
    ) -> None:
        transport.add(
            "POST",
            "/proxy/google/v1/models",
            json_body={"models": []},
        )
        resp = await async_client.proxy.request("google", "v1/models")
        assert resp.status_code == 200

    async def test_proxy_mcp(
        self,
        async_client: AsyncAgentGateClient,
        transport: MockTransport,
    ) -> None:
        transport.add(
            "POST",
            "/mcp/my-server",
            json_body={"jsonrpc": "2.0", "result": {}, "id": 1},
        )
        result = await async_client.proxy.mcp(
            "my-server",
            jsonrpc_body={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        )
        assert "result" in result

    async def test_config_list_policies(
        self,
        async_client: AsyncAgentGateClient,
        transport: MockTransport,
    ) -> None:
        transport.add("GET", "/policies", json_body=[POLICY_DATA])
        policies = await async_client.config.list_policies()
        assert len(policies) == 1

    async def test_config_register_webhook(
        self,
        async_client: AsyncAgentGateClient,
        transport: MockTransport,
    ) -> None:
        transport.add(
            "POST",
            "/webhooks",
            json_body={"status": "registered", "url": "http://x", "events": ["deny"]},
        )
        result = await async_client.config.register_webhook("http://x")
        assert result["status"] == "registered"

    async def test_config_register_mcp_server(
        self,
        async_client: AsyncAgentGateClient,
        transport: MockTransport,
    ) -> None:
        transport.add(
            "POST",
            "/mcp/servers",
            json_body={
                "status": "registered",
                "name": "fs",
                "url": "http://localhost:3000",
                "tools_registered": 0,
                "auto_policy": None,
            },
        )
        result = await async_client.config.register_mcp_server(
            "http://localhost:3000", name="fs"
        )
        assert result["name"] == "fs"

    async def test_exception_mapping_async(
        self,
        transport: MockTransport,
        async_transport: AsyncMockTransport,
    ) -> None:
        transport.add(
            "GET", "/health", status=401, json_body={"detail": "Unauthorized"}
        )
        client = AsyncAgentGateClient(
            base_url="http://test", transport=async_transport
        )
        with pytest.raises(AuthenticationError):
            await client.health()


# ── Context Manager Tests ────────────────────────────────────────────


class TestContextManager:
    def test_sync_context_manager(self, transport: MockTransport) -> None:
        transport.add("GET", "/health", json_body=HEALTH_DATA)
        with AgentGateClient(
            base_url="http://test", transport=transport
        ) as client:
            result = client.health()
            assert result.status == "ok"

    async def test_async_context_manager(
        self,
        transport: MockTransport,
        async_transport: AsyncMockTransport,
    ) -> None:
        transport.add("GET", "/health", json_body=HEALTH_DATA)
        async with AsyncAgentGateClient(
            base_url="http://test", transport=async_transport
        ) as client:
            result = await client.health()
            assert result.status == "ok"
