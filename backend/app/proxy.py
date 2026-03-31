"""Reverse proxy — intercepts requests, applies policy, forwards via connectors."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

import httpx
from fastapi import Request, Response
from loguru import logger

from .audit import AuditLogger
from .connectors import get_connector
from .connectors.base import BaseConnector
from .intent import IntentAnalyzer, IntentResult
from .path_normalize import normalize_path
from .policy import PolicyEngine
from .rate_limiter import RateLimiter
from .webhook import WebhookNotifier

# Headers that should not be forwarded from upstream responses
_EXCLUDED_RESPONSE_HEADERS = frozenset(
    {
        "transfer-encoding",
        "content-encoding",
        "content-length",
    }
)


class ReverseProxy:
    """HTTP reverse proxy with multi-provider support, intent analysis, and audit logging."""

    def __init__(
        self,
        *,
        policy_engine: PolicyEngine,
        audit_logger: AuditLogger,
        intent_analyzer: IntentAnalyzer,
        webhook_notifier: WebhookNotifier | None = None,
    ) -> None:
        self._policy = policy_engine
        self._audit = audit_logger
        self._intent = intent_analyzer
        self._rate_limiter = RateLimiter()
        self._webhook = webhook_notifier
        self._client = httpx.AsyncClient(timeout=30.0)

    async def handle(
        self, request: Request, agent: dict[str, Any], provider: str
    ) -> Response:
        """Process a proxied request: resolve connector → analyze intent → evaluate policy → forward or deny."""
        request_id = str(uuid.uuid4())[:8]
        start = time.perf_counter()

        # Resolve connector
        connector = get_connector(provider)
        if connector is None:
            return Response(
                content=json.dumps(
                    {
                        "error": "unknown_provider",
                        "detail": f"Provider '{provider}' is not supported",
                    }
                ),
                status_code=400,
                media_type="application/json",
            )

        # Verify agent is authorized for this provider
        agent_provider = agent.get("provider", "")
        if agent_provider and agent_provider != provider:
            return Response(
                content=json.dumps(
                    {
                        "error": "provider_mismatch",
                        "detail": f"Agent '{agent['name']}' is registered for provider '{agent_provider}', not '{provider}'",
                    }
                ),
                status_code=403,
                media_type="application/json",
            )

        # Extract proxy path (strip /proxy/{provider} prefix)
        proxy_path = self._extract_proxy_path(request.url.path, provider)
        method = request.method.upper()
        policy_name: str = agent.get("policy", "default")

        # Rate limit check
        policy_obj = self._policy.get_policy(policy_name)
        if policy_obj:
            rl_result = self._rate_limiter.check(
                agent["agent_id"], policy_obj.rate_limit
            )
            if not rl_result.allowed:
                return await self._handle_rate_limited(
                    agent=agent,
                    method=method,
                    proxy_path=proxy_path,
                    provider=provider,
                    request_id=request_id,
                    start=start,
                    retry_after=rl_result.retry_after or 1,
                    limit=rl_result.limit,
                    window=rl_result.window,
                )

        # Analyze intent (L1 → L2 → L3 fallback)
        body_bytes = await request.body()
        intent = await self._intent.analyze(method, proxy_path, provider, body_bytes)

        # Evaluate policy
        decision = self._policy.evaluate(policy_name, method, proxy_path, intent=intent)

        if decision.effect == "deny":
            return await self._handle_deny(
                agent=agent,
                method=method,
                proxy_path=proxy_path,
                provider=provider,
                reason=decision.reason,
                policy_name=policy_name,
                intent=intent,
                request_id=request_id,
                start=start,
            )

        # Record request for rate limiting (only on allow)
        self._rate_limiter.record(agent["agent_id"])

        return await self._forward_request(
            request=request,
            connector=connector,
            agent=agent,
            method=method,
            proxy_path=proxy_path,
            provider=provider,
            intent=intent,
            body=body_bytes,
            request_id=request_id,
            start=start,
        )

    async def _handle_deny(
        self,
        *,
        agent: dict[str, Any],
        method: str,
        proxy_path: str,
        provider: str,
        reason: str | None,
        policy_name: str,
        intent: IntentResult,
        request_id: str,
        start: float,
    ) -> Response:
        """Log and return a 403 denial response with structured feedback."""
        latency = (time.perf_counter() - start) * 1000
        logger.warning(
            f"[{request_id}] DENIED {method} {provider}:{proxy_path} "
            f"| agent={agent['name']} | intent={intent.intent_type} | reason={reason}"
        )
        await self._audit.log(
            agent_id=agent["agent_id"],
            agent_name=agent["name"],
            method=method,
            path=proxy_path,
            provider=provider,
            decision="deny",
            deny_reason=reason,
            intent=intent.intent_type,
            intent_confidence=intent.confidence,
            status_code=403,
            latency_ms=latency,
            request_id=request_id,
        )
        if self._webhook:
            await self._webhook.notify(
                "deny",
                {
                    "agent_id": agent["agent_id"],
                    "agent_name": agent["name"],
                    "method": method,
                    "path": proxy_path,
                    "provider": provider,
                    "reason": reason,
                    "intent": intent.intent_type,
                    "request_id": request_id,
                },
            )
        return Response(
            content=_deny_json(reason, request_id, policy_name, intent),
            status_code=403,
            media_type="application/json",
        )

    async def _handle_rate_limited(
        self,
        *,
        agent: dict[str, Any],
        method: str,
        proxy_path: str,
        provider: str,
        request_id: str,
        start: float,
        retry_after: int,
        limit: int,
        window: str,
    ) -> Response:
        """Log and return a 429 rate-limited response."""
        latency = (time.perf_counter() - start) * 1000
        logger.warning(
            f"[{request_id}] RATE_LIMITED {method} {provider}:{proxy_path} "
            f"| agent={agent['name']} | limit={limit}/{window}"
        )
        await self._audit.log(
            agent_id=agent["agent_id"],
            agent_name=agent["name"],
            method=method,
            path=proxy_path,
            provider=provider,
            decision="rate_limited",
            deny_reason=f"Rate limit exceeded: {limit} requests per {window}",
            status_code=429,
            latency_ms=latency,
            request_id=request_id,
        )
        if self._webhook:
            await self._webhook.notify(
                "rate_limited",
                {
                    "agent_id": agent["agent_id"],
                    "agent_name": agent["name"],
                    "method": method,
                    "path": proxy_path,
                    "provider": provider,
                    "limit": limit,
                    "window": window,
                    "request_id": request_id,
                },
            )
        body = json.dumps(
            {
                "error": "rate_limited",
                "detail": f"Rate limit exceeded: {limit} requests per {window}",
                "retry_after": retry_after,
                "request_id": request_id,
            }
        )
        return Response(
            content=body,
            status_code=429,
            media_type="application/json",
            headers={"Retry-After": str(retry_after)},
        )

    async def _forward_request(
        self,
        *,
        request: Request,
        connector: BaseConnector,
        agent: dict[str, Any],
        method: str,
        proxy_path: str,
        provider: str,
        intent: IntentResult,
        body: bytes,
        request_id: str,
        start: float,
    ) -> Response:
        """Forward the request to the upstream target via connector."""
        target_url = connector.build_target_url(proxy_path, str(request.url.query))
        forward_headers = connector.build_forward_headers(request)

        try:
            resp = await self._client.request(
                method=method,
                url=target_url,
                headers=forward_headers,
                content=body if body else None,
            )
            latency = (time.perf_counter() - start) * 1000
            logger.info(
                f"[{request_id}] ALLOW {method} {provider}:{proxy_path} "
                f"-> {resp.status_code} ({latency:.1f}ms) | agent={agent['name']}"
            )
            await self._audit.log(
                agent_id=agent["agent_id"],
                agent_name=agent["name"],
                method=method,
                path=proxy_path,
                provider=provider,
                decision="allow",
                intent=intent.intent_type,
                intent_confidence=intent.confidence,
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
            logger.error(
                f"[{request_id}] PROXY ERROR {method} {provider}:{proxy_path}: {exc}"
            )
            await self._audit.log(
                agent_id=agent["agent_id"],
                agent_name=agent["name"],
                method=method,
                path=proxy_path,
                provider=provider,
                decision="error",
                deny_reason=f"proxy_error: {exc}",
                intent=intent.intent_type,
                intent_confidence=intent.confidence,
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
    def _extract_proxy_path(url_path: str, provider: str) -> str:
        """Strip the /proxy/{provider} prefix and normalize the path."""
        prefix = f"/proxy/{provider}"
        if url_path.startswith(prefix):
            path = url_path[len(prefix) :]
            return normalize_path(path) if path else "/"
        return normalize_path(url_path)


def _deny_json(
    reason: str | None, request_id: str, policy: str, intent: IntentResult
) -> str:
    """Build a JSON denial response body with structured feedback."""
    suggestion = _suggest_alternative(intent)
    return json.dumps(
        {
            "error": "access_denied",
            "reason": reason or "Denied by policy",
            "intent": {
                "type": intent.intent_type,
                "resource": intent.resource_type,
                "confidence": intent.confidence,
                "level": intent.analysis_level,
            },
            "suggestion": suggestion,
            "request_id": request_id,
            "policy": policy,
        }
    )


_SUGGESTIONS: dict[str, str] = {
    "delete": "Use GET to read resources instead, or request a policy that permits delete operations.",
    "create": "Your current policy does not allow creating resources. Request a 'readwrite' policy.",
    "update": "Your current policy does not allow updates. Request a 'readwrite' policy.",
    "unknown": "Check the policy assigned to your agent. Use GET /policies to view available policies.",
}


def _suggest_alternative(intent: IntentResult) -> str:
    """Generate a helpful suggestion based on the denied intent."""
    return _SUGGESTIONS.get(intent.intent_type, _SUGGESTIONS["unknown"])
