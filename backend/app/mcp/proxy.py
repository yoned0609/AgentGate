"""MCP Auth Proxy — intercepts JSON-RPC tool calls and applies policy.

MCP uses JSON-RPC 2.0 over HTTP (Streamable HTTP transport).
This proxy intercepts `tools/call` requests, evaluates them against
AgentGate policies, and either forwards to the upstream MCP Server
or returns a policy denial.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import httpx
from loguru import logger

from ..audit import AuditLogger
from ..intent import IntentResult
from ..policy import PolicyEngine
from .annotations import classify_tool_intent


class MCPAuthProxy:
    """Proxy for MCP JSON-RPC requests with authorization."""

    def __init__(
        self,
        *,
        upstream_url: str,
        policy_engine: PolicyEngine,
        audit_logger: AuditLogger,
        tool_annotations: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self._upstream_url = upstream_url.rstrip("/")
        self._policy = policy_engine
        self._audit = audit_logger
        self._tool_annotations = tool_annotations or {}
        self._client = httpx.AsyncClient(timeout=30.0)

    def register_tool_annotations(self, tools: list[dict[str, Any]]) -> None:
        """Register MCP tool definitions for annotation-based intent classification."""
        for tool in tools:
            name = tool.get("name", "")
            annotations = tool.get("annotations", {})
            if name:
                self._tool_annotations[name] = annotations
        logger.info(
            f"MCP: Registered annotations for {len(self._tool_annotations)} tools"
        )

    async def handle_jsonrpc(
        self,
        body: dict[str, Any],
        *,
        agent_id: str,
        agent_name: str,
        policy_name: str,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Process a JSON-RPC request.

        Intercepts tools/call for policy evaluation.
        All other methods are forwarded transparently.
        """
        request_id = str(uuid.uuid4())[:8]
        method = body.get("method", "")
        jsonrpc_id = body.get("id")

        # Only intercept tools/call
        if method != "tools/call":
            return await self._forward(body, headers=headers)

        params = body.get("params", {})
        tool_name = params.get("name", "unknown")
        start = time.perf_counter()

        # Classify intent from tool annotations
        annotations = self._tool_annotations.get(tool_name, {})
        intent_type = classify_tool_intent(tool_name, annotations)
        intent = IntentResult(
            intent_type=intent_type,
            resource_type=f"mcp_tool:{tool_name}",
            confidence=0.9 if annotations else 0.5,
            analysis_level="L2" if annotations else "L1",
        )

        # Build a virtual path for policy evaluation
        virtual_path = f"/mcp/tools/{tool_name}"

        # Evaluate policy
        decision = self._policy.evaluate(
            policy_name, "POST", virtual_path, intent=intent
        )

        if decision.effect == "deny":
            latency = (time.perf_counter() - start) * 1000
            logger.warning(
                f"[{request_id}] MCP DENIED tools/call:{tool_name} "
                f"| agent={agent_name} | intent={intent_type} | reason={decision.reason}"
            )
            await self._audit.log(
                agent_id=agent_id,
                agent_name=agent_name,
                method="MCP:tools/call",
                path=virtual_path,
                provider="mcp",
                decision="deny",
                deny_reason=decision.reason,
                intent=intent_type,
                intent_confidence=intent.confidence,
                status_code=403,
                latency_ms=latency,
                request_id=request_id,
            )
            return _jsonrpc_error(
                jsonrpc_id,
                code=-32600,
                message="Access denied by AgentGate policy",
                data={
                    "tool": tool_name,
                    "intent": intent_type,
                    "reason": decision.reason,
                    "request_id": request_id,
                },
            )

        # Forward to upstream MCP server
        result = await self._forward(body, headers=headers)
        latency = (time.perf_counter() - start) * 1000

        logger.info(
            f"[{request_id}] MCP ALLOW tools/call:{tool_name} "
            f"({latency:.1f}ms) | agent={agent_name}"
        )
        await self._audit.log(
            agent_id=agent_id,
            agent_name=agent_name,
            method="MCP:tools/call",
            path=virtual_path,
            provider="mcp",
            decision="allow",
            intent=intent_type,
            intent_confidence=intent.confidence,
            status_code=200,
            latency_ms=latency,
            request_id=request_id,
        )

        return result

    async def _forward(
        self,
        body: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Forward JSON-RPC request to upstream MCP server."""
        forward_headers = {"Content-Type": "application/json"}
        if headers:
            forward_headers.update(headers)

        try:
            resp = await self._client.post(
                self._upstream_url,
                json=body,
                headers=forward_headers,
            )
            return resp.json()
        except httpx.RequestError as exc:
            logger.error(f"MCP upstream error: {exc}")
            return _jsonrpc_error(
                body.get("id"),
                code=-32603,
                message=f"MCP upstream error: {exc}",
            )
        except Exception as exc:
            return _jsonrpc_error(
                body.get("id"),
                code=-32603,
                message=f"Internal error: {exc}",
            )

    async def close(self) -> None:
        await self._client.aclose()


def _jsonrpc_error(
    id: Any,
    *,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error response."""
    error: dict[str, Any] = {"code": code, "message": message}
    if data:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": id, "error": error}
