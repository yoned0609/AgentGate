"""Sync and async clients for the AgentGate API."""

from __future__ import annotations

from typing import Any

import httpx

from .exceptions import raise_for_status
from .models import (
    Agent,
    AgentCreateParams,
    AgentStats,
    AlertThresholdCreateParams,
    AuditExport,
    AuditLogList,
    AuditPurgeResult,
    HealthStatus,
    MCPServerCreateParams,
    PolicyInfo,
    WebhookCreateParams,
)

# ── Resource namespaces (sync) ───────────────────────────────────────


class _AgentsResource:
    """Agent management endpoints (requires master key)."""

    def __init__(self, http: httpx.Client) -> None:
        self._http = http

    def create(
        self,
        name: str,
        *,
        description: str = "",
        policy: str = "default",
        provider: str = "google",
    ) -> Agent:
        params = AgentCreateParams(
            name=name, description=description, policy=policy, provider=provider
        )
        resp = self._http.post("/agents", json=params.model_dump())
        raise_for_status(resp)
        return Agent.model_validate(resp.json())

    def list(self) -> list[Agent]:
        resp = self._http.get("/agents")
        raise_for_status(resp)
        return [Agent.model_validate(a) for a in resp.json()]

    def delete(self, agent_id: str) -> dict:
        resp = self._http.delete(f"/agents/{agent_id}")
        raise_for_status(resp)
        return resp.json()

    def rotate_key(self, agent_id: str) -> Agent:
        resp = self._http.post(f"/agents/{agent_id}/rotate-key")
        raise_for_status(resp)
        return Agent.model_validate(resp.json())

    def stats(self, agent_id: str) -> AgentStats:
        resp = self._http.get(f"/agents/{agent_id}/stats")
        raise_for_status(resp)
        return AgentStats.model_validate(resp.json())


class _AuditResource:
    """Audit log endpoints (requires master key)."""

    def __init__(self, http: httpx.Client) -> None:
        self._http = http

    def logs(
        self,
        *,
        agent_id: str | None = None,
        decision: str | None = None,
        provider: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> AuditLogList:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if agent_id is not None:
            params["agent_id"] = agent_id
        if decision is not None:
            params["decision"] = decision
        if provider is not None:
            params["provider"] = provider
        resp = self._http.get("/audit/logs", params=params)
        raise_for_status(resp)
        return AuditLogList.model_validate(resp.json())

    def stats(
        self,
        *,
        agent_id: str | None = None,
        provider: str | None = None,
    ) -> dict:
        params: dict[str, Any] = {}
        if agent_id is not None:
            params["agent_id"] = agent_id
        if provider is not None:
            params["provider"] = provider
        resp = self._http.get("/audit/stats", params=params)
        raise_for_status(resp)
        return resp.json()

    def export(
        self,
        *,
        agent_id: str | None = None,
        decision: str | None = None,
        provider: str | None = None,
        format: str = "json",
        limit: int = 10000,
    ) -> AuditExport | httpx.Response:
        params: dict[str, Any] = {"format": format, "limit": limit}
        if agent_id is not None:
            params["agent_id"] = agent_id
        if decision is not None:
            params["decision"] = decision
        if provider is not None:
            params["provider"] = provider
        resp = self._http.get("/audit/export", params=params)
        raise_for_status(resp)
        if format == "csv":
            return resp
        return AuditExport.model_validate(resp.json())

    def purge(self, *, retention_days: int = 90) -> AuditPurgeResult:
        resp = self._http.post(
            "/audit/purge", params={"retention_days": retention_days}
        )
        raise_for_status(resp)
        return AuditPurgeResult.model_validate(resp.json())


class _ProxyResource:
    """Proxy endpoints (requires agent key)."""

    def __init__(self, http: httpx.Client) -> None:
        self._http = http

    def request(
        self,
        provider: str,
        path: str,
        *,
        method: str = "POST",
        json: dict | None = None,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        url = f"/proxy/{provider}/{path}"
        resp = self._http.request(
            method, url, json=json, headers=headers, content=content
        )
        raise_for_status(resp)
        return resp

    def mcp(
        self,
        server_name: str,
        *,
        jsonrpc_body: dict,
    ) -> dict:
        resp = self._http.post(f"/mcp/{server_name}", json=jsonrpc_body)
        raise_for_status(resp)
        return resp.json()


class _ConfigResource:
    """Configuration endpoints (requires master key)."""

    def __init__(self, http: httpx.Client) -> None:
        self._http = http

    def list_policies(self) -> list[PolicyInfo]:
        resp = self._http.get("/policies")
        raise_for_status(resp)
        return [PolicyInfo.model_validate(p) for p in resp.json()]

    def register_webhook(
        self,
        url: str,
        *,
        events: list[str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict:
        params = WebhookCreateParams(
            url=url,
            events=events or ["deny", "rate_limited"],
            headers=headers or {},
        )
        resp = self._http.post("/webhooks", json=params.model_dump())
        raise_for_status(resp)
        return resp.json()

    def register_alert_threshold(
        self,
        *,
        event: str = "deny",
        count: int = 10,
        window_seconds: int = 300,
        agent_id: str | None = None,
    ) -> dict:
        params = AlertThresholdCreateParams(
            event=event, count=count, window_seconds=window_seconds, agent_id=agent_id
        )
        resp = self._http.post("/alerts/thresholds", json=params.model_dump())
        raise_for_status(resp)
        return resp.json()

    def register_mcp_server(
        self,
        url: str,
        *,
        name: str = "",
        tools: list[dict] | None = None,
    ) -> dict:
        params = MCPServerCreateParams(url=url, name=name, tools=tools or [])
        resp = self._http.post("/mcp/servers", json=params.model_dump())
        raise_for_status(resp)
        return resp.json()


# ── Resource namespaces (async) ──────────────────────────────────────


class _AsyncAgentsResource:
    """Agent management endpoints (async, requires master key)."""

    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def create(
        self,
        name: str,
        *,
        description: str = "",
        policy: str = "default",
        provider: str = "google",
    ) -> Agent:
        params = AgentCreateParams(
            name=name, description=description, policy=policy, provider=provider
        )
        resp = await self._http.post("/agents", json=params.model_dump())
        raise_for_status(resp)
        return Agent.model_validate(resp.json())

    async def list(self) -> list[Agent]:
        resp = await self._http.get("/agents")
        raise_for_status(resp)
        return [Agent.model_validate(a) for a in resp.json()]

    async def delete(self, agent_id: str) -> dict:
        resp = await self._http.delete(f"/agents/{agent_id}")
        raise_for_status(resp)
        return resp.json()

    async def rotate_key(self, agent_id: str) -> Agent:
        resp = await self._http.post(f"/agents/{agent_id}/rotate-key")
        raise_for_status(resp)
        return Agent.model_validate(resp.json())

    async def stats(self, agent_id: str) -> AgentStats:
        resp = await self._http.get(f"/agents/{agent_id}/stats")
        raise_for_status(resp)
        return AgentStats.model_validate(resp.json())


class _AsyncAuditResource:
    """Audit log endpoints (async, requires master key)."""

    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def logs(
        self,
        *,
        agent_id: str | None = None,
        decision: str | None = None,
        provider: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> AuditLogList:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if agent_id is not None:
            params["agent_id"] = agent_id
        if decision is not None:
            params["decision"] = decision
        if provider is not None:
            params["provider"] = provider
        resp = await self._http.get("/audit/logs", params=params)
        raise_for_status(resp)
        return AuditLogList.model_validate(resp.json())

    async def stats(
        self,
        *,
        agent_id: str | None = None,
        provider: str | None = None,
    ) -> dict:
        params: dict[str, Any] = {}
        if agent_id is not None:
            params["agent_id"] = agent_id
        if provider is not None:
            params["provider"] = provider
        resp = await self._http.get("/audit/stats", params=params)
        raise_for_status(resp)
        return resp.json()

    async def export(
        self,
        *,
        agent_id: str | None = None,
        decision: str | None = None,
        provider: str | None = None,
        format: str = "json",
        limit: int = 10000,
    ) -> AuditExport | httpx.Response:
        params: dict[str, Any] = {"format": format, "limit": limit}
        if agent_id is not None:
            params["agent_id"] = agent_id
        if decision is not None:
            params["decision"] = decision
        if provider is not None:
            params["provider"] = provider
        resp = await self._http.get("/audit/export", params=params)
        raise_for_status(resp)
        if format == "csv":
            return resp
        return AuditExport.model_validate(resp.json())

    async def purge(self, *, retention_days: int = 90) -> AuditPurgeResult:
        resp = await self._http.post(
            "/audit/purge", params={"retention_days": retention_days}
        )
        raise_for_status(resp)
        return AuditPurgeResult.model_validate(resp.json())


class _AsyncProxyResource:
    """Proxy endpoints (async, requires agent key)."""

    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def request(
        self,
        provider: str,
        path: str,
        *,
        method: str = "POST",
        json: dict | None = None,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        url = f"/proxy/{provider}/{path}"
        resp = await self._http.request(
            method, url, json=json, headers=headers, content=content
        )
        raise_for_status(resp)
        return resp

    async def mcp(
        self,
        server_name: str,
        *,
        jsonrpc_body: dict,
    ) -> dict:
        resp = await self._http.post(f"/mcp/{server_name}", json=jsonrpc_body)
        raise_for_status(resp)
        return resp.json()


class _AsyncConfigResource:
    """Configuration endpoints (async, requires master key)."""

    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def list_policies(self) -> list[PolicyInfo]:
        resp = await self._http.get("/policies")
        raise_for_status(resp)
        return [PolicyInfo.model_validate(p) for p in resp.json()]

    async def register_webhook(
        self,
        url: str,
        *,
        events: list[str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict:
        params = WebhookCreateParams(
            url=url,
            events=events or ["deny", "rate_limited"],
            headers=headers or {},
        )
        resp = await self._http.post("/webhooks", json=params.model_dump())
        raise_for_status(resp)
        return resp.json()

    async def register_alert_threshold(
        self,
        *,
        event: str = "deny",
        count: int = 10,
        window_seconds: int = 300,
        agent_id: str | None = None,
    ) -> dict:
        params = AlertThresholdCreateParams(
            event=event, count=count, window_seconds=window_seconds, agent_id=agent_id
        )
        resp = await self._http.post("/alerts/thresholds", json=params.model_dump())
        raise_for_status(resp)
        return resp.json()

    async def register_mcp_server(
        self,
        url: str,
        *,
        name: str = "",
        tools: list[dict] | None = None,
    ) -> dict:
        params = MCPServerCreateParams(url=url, name=name, tools=tools or [])
        resp = await self._http.post("/mcp/servers", json=params.model_dump())
        raise_for_status(resp)
        return resp.json()


# ── Main clients ─────────────────────────────────────────────────────


class AgentGateClient:
    """Synchronous client for the AgentGate API.

    Args:
        base_url: Base URL of the AgentGate server (e.g. ``http://localhost:8000``).
        master_key: Master API key for admin endpoints.
        agent_key: Agent API key for proxy endpoints.
        timeout: Request timeout in seconds.
        transport: Optional httpx transport (useful for testing).
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        *,
        master_key: str | None = None,
        agent_key: str | None = None,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        headers: dict[str, str] = {}
        if master_key:
            headers["X-Master-Key"] = master_key
        if agent_key:
            headers["X-Agent-Key"] = agent_key

        self._http = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
            transport=transport,
        )

        self.agents = _AgentsResource(self._http)
        self.audit = _AuditResource(self._http)
        self.proxy = _ProxyResource(self._http)
        self.config = _ConfigResource(self._http)

    # ── Discovery (no auth) ──────────────────────────────────────────

    def health(self) -> HealthStatus:
        resp = self._http.get("/health")
        raise_for_status(resp)
        return HealthStatus.model_validate(resp.json())

    def providers(self) -> list[str]:
        resp = self._http.get("/providers")
        raise_for_status(resp)
        return resp.json()["providers"]

    # ── Lifecycle ────────────────────────────────────────────────────

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "AgentGateClient":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class AsyncAgentGateClient:
    """Asynchronous client for the AgentGate API.

    Args:
        base_url: Base URL of the AgentGate server (e.g. ``http://localhost:8000``).
        master_key: Master API key for admin endpoints.
        agent_key: Agent API key for proxy endpoints.
        timeout: Request timeout in seconds.
        transport: Optional httpx async transport (useful for testing).
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        *,
        master_key: str | None = None,
        agent_key: str | None = None,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        headers: dict[str, str] = {}
        if master_key:
            headers["X-Master-Key"] = master_key
        if agent_key:
            headers["X-Agent-Key"] = agent_key

        self._http = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
            transport=transport,
        )

        self.agents = _AsyncAgentsResource(self._http)
        self.audit = _AsyncAuditResource(self._http)
        self.proxy = _AsyncProxyResource(self._http)
        self.config = _AsyncConfigResource(self._http)

    # ── Discovery (no auth) ──────────────────────────────────────────

    async def health(self) -> HealthStatus:
        resp = await self._http.get("/health")
        raise_for_status(resp)
        return HealthStatus.model_validate(resp.json())

    async def providers(self) -> list[str]:
        resp = await self._http.get("/providers")
        raise_for_status(resp)
        return resp.json()["providers"]

    # ── Lifecycle ────────────────────────────────────────────────────

    async def close(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "AsyncAgentGateClient":
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()
