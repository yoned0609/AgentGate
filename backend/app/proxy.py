"""Reverse proxy — intercepts requests, applies policy, forwards to target API."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

import httpx
from fastapi import Request, Response
from loguru import logger

from .audit import AuditLogger
from .policy import PolicyEngine

# Headers that should not be forwarded from upstream responses
_EXCLUDED_RESPONSE_HEADERS = frozenset({
    "transfer-encoding",
    "content-encoding",
    "content-length",
})


class ReverseProxy:
    """HTTP reverse proxy with policy enforcement and audit logging."""

    def __init__(
        self,
        *,
        target_base_url: str,
        policy_engine: PolicyEngine,
        audit_logger: AuditLogger,
    ) -> None:
        self._target = target_base_url.rstrip("/")
        self._policy = policy_engine
        self._audit = audit_logger
        self._client = httpx.AsyncClient(timeout=30.0)

    async def handle(self, request: Request, agent: dict[str, Any]) -> Response:
        """Process a proxied request: evaluate policy, then forward or deny."""
        request_id = str(uuid.uuid4())[:8]
        start = time.perf_counter()

        proxy_path = self._extract_proxy_path(request.url.path)
        method = request.method.upper()
        policy_name: str = agent.get("policy", "default")

        # Evaluate policy
        decision = self._policy.evaluate(policy_name, method, proxy_path)

        if decision.effect == "deny":
            return await self._handle_deny(
                agent=agent,
                method=method,
                proxy_path=proxy_path,
                reason=decision.reason,
                policy_name=policy_name,
                request_id=request_id,
                start=start,
            )

        return await self._forward_request(
            request=request,
            agent=agent,
            method=method,
            proxy_path=proxy_path,
            request_id=request_id,
            start=start,
        )

    async def _handle_deny(
        self,
        *,
        agent: dict[str, Any],
        method: str,
        proxy_path: str,
        reason: str | None,
        policy_name: str,
        request_id: str,
        start: float,
    ) -> Response:
        """Log and return a 403 denial response."""
        latency = (time.perf_counter() - start) * 1000
        logger.warning(
            f"[{request_id}] DENIED {method} {proxy_path} "
            f"| agent={agent['name']} | reason={reason}"
        )
        await self._audit.log(
            agent_id=agent["agent_id"],
            agent_name=agent["name"],
            method=method,
            path=proxy_path,
            decision="deny",
            deny_reason=reason,
            status_code=403,
            latency_ms=latency,
            request_id=request_id,
        )
        return Response(
            content=_deny_json(reason, request_id, policy_name),
            status_code=403,
            media_type="application/json",
        )

    async def _forward_request(
        self,
        *,
        request: Request,
        agent: dict[str, Any],
        method: str,
        proxy_path: str,
        request_id: str,
        start: float,
    ) -> Response:
        """Forward the request to the upstream target and return the response."""
        target_url = f"{self._target}{proxy_path}"
        query = str(request.url.query)
        if query:
            target_url = f"{target_url}?{query}"

        forward_headers = self._build_forward_headers(request)
        body = await request.body()

        try:
            resp = await self._client.request(
                method=method,
                url=target_url,
                headers=forward_headers,
                content=body if body else None,
            )
            latency = (time.perf_counter() - start) * 1000
            logger.info(
                f"[{request_id}] ALLOW {method} {proxy_path} "
                f"-> {resp.status_code} ({latency:.1f}ms) | agent={agent['name']}"
            )
            await self._audit.log(
                agent_id=agent["agent_id"],
                agent_name=agent["name"],
                method=method,
                path=proxy_path,
                decision="allow",
                status_code=resp.status_code,
                latency_ms=latency,
                request_id=request_id,
            )

            resp_headers = {
                k: v
                for k, v in resp.headers.items()
                if k.lower() not in _EXCLUDED_RESPONSE_HEADERS
            }
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers=resp_headers,
                media_type=resp.headers.get("content-type"),
            )

        except httpx.RequestError as exc:
            latency = (time.perf_counter() - start) * 1000
            logger.error(f"[{request_id}] PROXY ERROR {method} {proxy_path}: {exc}")
            await self._audit.log(
                agent_id=agent["agent_id"],
                agent_name=agent["name"],
                method=method,
                path=proxy_path,
                decision="error",
                deny_reason=f"proxy_error: {exc}",
                status_code=502,
                latency_ms=latency,
                request_id=request_id,
            )
            return Response(
                content=json.dumps({"error": "proxy_error", "detail": str(exc)}),
                status_code=502,
                media_type="application/json",
            )

    async def close(self) -> None:
        """Shut down the underlying HTTP client."""
        await self._client.aclose()

    @staticmethod
    def _extract_proxy_path(url_path: str) -> str:
        """Strip the /proxy prefix from the request path."""
        path = url_path
        if path.startswith("/proxy"):
            path = path[len("/proxy"):]
        return path or "/"

    @staticmethod
    def _build_forward_headers(request: Request) -> dict[str, str]:
        """Extract headers that should be forwarded to the upstream target."""
        headers: dict[str, str] = {}
        if "authorization" in request.headers:
            headers["Authorization"] = request.headers["authorization"]
        if "content-type" in request.headers:
            headers["Content-Type"] = request.headers["content-type"]
        return headers


def _deny_json(reason: str | None, request_id: str, policy: str) -> str:
    """Build a JSON denial response body."""
    return json.dumps({
        "error": "access_denied",
        "reason": reason or "Denied by policy",
        "request_id": request_id,
        "policy": policy,
    })
