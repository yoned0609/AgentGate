"""AgentGate — JIT Authorization Proxy for AI Agents."""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from .agents import AgentStore
from .audit import AuditLogger
from .config import settings
from .connectors import available_providers
from .intent import IntentAnalyzer
from .middleware.security import SecurityHeadersMiddleware
from .middleware.validation import RequestValidationMiddleware
from .models import (
    AgentCreate,
    AgentResponse,
    AgentStats,
    AlertThresholdCreate,
    AuditLogList,
    HealthResponse,
    PolicyInfo,
    WebhookCreate,
)
from .analytics import AnalyticsEngine
from .l3_escalation import L3EscalationManager
from .policy import PolicyEngine
from .policy_builder import PolicyBuildRequest, build_policy
from .mcp.annotations import tools_to_policy
from .mcp.proxy import MCPAuthProxy
from .proxy import ReverseProxy
from .webhook import AlertThreshold, WebhookConfig, WebhookNotifier
from .workflow import WorkflowEngine, WorkflowRule

# ── Logging ──────────────────────────────────────────────────────────
_LOG_DIR = Path("logs")
_LOG_DIR.mkdir(exist_ok=True)

logger.remove()
logger.add(
    sys.stdout,
    level="DEBUG" if settings.debug else "INFO",
    format="{time:HH:mm:ss} | {level:<7} | {message}",
)
logger.add(
    _LOG_DIR / "agentgate.log",
    rotation="10 MB",
    retention="30 days",
    level="INFO",
    encoding="utf-8",
)
logger.add(
    _LOG_DIR / "agentgate_error.log",
    rotation="10 MB",
    retention="90 days",
    level="ERROR",
    encoding="utf-8",
)

# ── Core components ──────────────────────────────────────────────────
policy_engine = PolicyEngine(policy_dir=settings.policy_dir)
audit_logger = AuditLogger(db_path=settings.audit_db_path)
agent_store = AgentStore()
webhook_notifier = WebhookNotifier()
l3_manager = L3EscalationManager(webhook_notifier=webhook_notifier)
intent_analyzer = IntentAnalyzer(l3_callback=l3_manager.escalate)
analytics_engine = AnalyticsEngine(db_path=settings.audit_db_path)
workflow_engine = WorkflowEngine()
reverse_proxy = ReverseProxy(
    policy_engine=policy_engine,
    audit_logger=audit_logger,
    intent_analyzer=intent_analyzer,
    webhook_notifier=webhook_notifier,
    workflow_engine=workflow_engine,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await agent_store._ensure_init()
    providers = available_providers()
    logger.info("AgentGate starting up")
    logger.info(f"Providers: {providers}")
    logger.info(f"Policies loaded: {policy_engine.policy_names}")
    logger.info(f"Agents registered: {agent_store.count}")
    yield
    await reverse_proxy.close()
    await webhook_notifier.close()
    logger.info("AgentGate shut down")


# ── App ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="AgentGate",
    description="JIT Authorization Proxy for AI Agents",
    version="0.3.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url=None,
    lifespan=lifespan,
)

# Middleware (outermost → innermost)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestValidationMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Auth helpers ─────────────────────────────────────────────────────
def _extract_agent_key(request: Request) -> str:
    """Extract agent API key from X-Agent-Key header."""
    key = request.headers.get("x-agent-key", "")
    if not key:
        raise HTTPException(status_code=401, detail="Missing X-Agent-Key header")
    return key


def _require_master(request: Request) -> None:
    """Require master API key for admin endpoints."""
    key = request.headers.get("x-master-key", "")
    if key != settings.master_api_key:
        raise HTTPException(status_code=403, detail="Invalid master key")


# ── Health ───────────────────────────────────────────────────────────
@app.get("/health", response_model=HealthResponse)
async def health():
    audit_ok = await audit_logger.is_healthy()
    return HealthResponse(
        status="ok" if audit_ok else "degraded",
        version="0.3.0",
        providers=available_providers(),
        policy_loaded=len(policy_engine.policy_names) > 0,
        agents_count=agent_store.count,
        audit_db="ok" if audit_ok else "error",
    )


# ── Agent Management (master key required) ───────────────────────────
@app.post("/agents", response_model=AgentResponse)
async def create_agent(body: AgentCreate, _=Depends(_require_master)):
    if body.policy not in policy_engine.policy_names:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown policy: {body.policy}. Available: {policy_engine.policy_names}",
        )
    if body.provider not in available_providers():
        raise HTTPException(
            status_code=400,
            detail=f"Unknown provider: {body.provider}. Available: {available_providers()}",
        )
    agent = await agent_store.create(
        name=body.name,
        description=body.description,
        policy=body.policy,
        provider=body.provider,
    )
    return AgentResponse(**agent)


@app.get("/agents", response_model=list[AgentResponse])
async def list_agents(_=Depends(_require_master)):
    return [AgentResponse(**a) for a in agent_store.list_all()]


@app.delete("/agents/{agent_id}")
async def delete_agent(agent_id: str, _=Depends(_require_master)):
    if not await agent_store.delete(agent_id):
        raise HTTPException(status_code=404, detail="Agent not found")
    return {"status": "deleted"}


@app.post("/agents/{agent_id}/rotate-key", response_model=AgentResponse)
async def rotate_agent_key(agent_id: str, _=Depends(_require_master)):
    agent = await agent_store.rotate_key(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return AgentResponse(**agent)


@app.get("/agents/{agent_id}/stats", response_model=AgentStats)
async def get_agent_stats(agent_id: str, _=Depends(_require_master)):
    stats = await agent_store.get_stats(agent_id)
    if stats is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return AgentStats(**stats)


# ── Providers ────────────────────────────────────────────────────────
@app.get("/providers")
async def list_providers():
    return {"providers": available_providers()}


# ── Policy Info ──────────────────────────────────────────────────────
@app.get("/policies", response_model=list[PolicyInfo])
async def list_policies(_=Depends(_require_master)):
    result = []
    for name in policy_engine.policy_names:
        p = policy_engine.get_policy(name)
        if p:
            result.append(PolicyInfo(name=p.name, rules=p.rules))
    return result


# ── Audit Logs ───────────────────────────────────────────────────────
@app.get("/audit/logs")
async def get_audit_logs(
    agent_id: str | None = None,
    decision: str | None = None,
    provider: str | None = None,
    limit: int = 50,
    offset: int = 0,
    pretty: bool = False,
    _=Depends(_require_master),
):
    logs, total = await audit_logger.query(
        agent_id=agent_id,
        decision=decision,
        provider=provider,
        limit=limit,
        offset=offset,
    )
    data = AuditLogList(logs=logs, total=total)
    if pretty:
        import json as _json

        return Response(
            content=_json.dumps(data.model_dump(), indent=2, ensure_ascii=False),
            media_type="application/json",
        )
    return data


@app.get("/audit/stats")
async def get_audit_stats(
    agent_id: str | None = None,
    provider: str | None = None,
    _=Depends(_require_master),
):
    return await audit_logger.stats(agent_id=agent_id, provider=provider)


@app.get("/audit/export")
async def export_audit_logs(
    agent_id: str | None = None,
    decision: str | None = None,
    provider: str | None = None,
    format: str = "json",
    limit: int = 10000,
    _=Depends(_require_master),
):
    logs = await audit_logger.export(
        agent_id=agent_id, decision=decision, provider=provider, limit=limit
    )
    if format == "csv":
        import csv
        import io

        if not logs:
            return Response(content="", media_type="text/csv")
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=logs[0].keys())
        writer.writeheader()
        writer.writerows(logs)
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_logs.csv"},
        )
    return {"logs": logs, "count": len(logs)}


@app.post("/audit/purge")
async def purge_audit_logs(
    retention_days: int = 90,
    _=Depends(_require_master),
):
    count = await audit_logger.purge(retention_days=retention_days)
    return {"purged": count, "retention_days": retention_days}


# ── Webhooks / Alerts ────────────────────────────────────────────────
@app.post("/webhooks")
async def register_webhook(body: WebhookCreate, _=Depends(_require_master)):
    webhook_notifier.add_webhook(
        WebhookConfig(url=body.url, events=body.events, headers=body.headers)
    )
    return {"status": "registered", "url": body.url, "events": body.events}


@app.post("/alerts/thresholds")
async def register_alert_threshold(
    body: AlertThresholdCreate, _=Depends(_require_master)
):
    webhook_notifier.add_threshold(
        AlertThreshold(
            event=body.event,
            count=body.count,
            window_seconds=body.window_seconds,
            agent_id=body.agent_id,
        )
    )
    return {
        "status": "registered",
        "event": body.event,
        "count": body.count,
        "window_seconds": body.window_seconds,
    }


# ── Analytics (master key required) ──────────────────────────────────
@app.get("/analytics/timeseries")
async def analytics_timeseries(
    interval: str = "hour",
    agent_id: str | None = None,
    provider: str | None = None,
    hours: int = 24,
    _=Depends(_require_master),
):
    """Time-series of request counts, deny counts, and latency."""
    return await analytics_engine.time_series(
        interval=interval, agent_id=agent_id, provider=provider, hours=hours,
    )


@app.get("/analytics/deny-trends")
async def analytics_deny_trends(
    agent_id: str | None = None,
    provider: str | None = None,
    hours: int = 24,
    _=Depends(_require_master),
):
    """Top deny reasons and deny rate over time."""
    return await analytics_engine.deny_trends(
        agent_id=agent_id, provider=provider, hours=hours,
    )


@app.get("/analytics/heatmap")
async def analytics_heatmap(
    hours: int = 24,
    _=Depends(_require_master),
):
    """Agent x provider activity heatmap data."""
    return await analytics_engine.agent_heatmap(hours=hours)


@app.get("/analytics/anomalies")
async def analytics_anomalies(
    window_minutes: int = 10,
    threshold: float = 3.0,
    _=Depends(_require_master),
):
    """Detect anomalous traffic spikes per agent."""
    return await analytics_engine.anomaly_detection(
        window_minutes=window_minutes, threshold_multiplier=threshold,
    )


@app.get("/analytics/latency")
async def analytics_latency(
    agent_id: str | None = None,
    provider: str | None = None,
    hours: int = 24,
    _=Depends(_require_master),
):
    """Latency percentiles (p50, p90, p95, p99)."""
    return await analytics_engine.latency_percentiles(
        agent_id=agent_id, provider=provider, hours=hours,
    )


@app.get("/analytics/intents")
async def analytics_intents(
    provider: str | None = None,
    hours: int = 24,
    _=Depends(_require_master),
):
    """Intent type distribution grouped by decision."""
    return await analytics_engine.intent_distribution(provider=provider, hours=hours)


# ── Natural Language Policy Builder (master key required) ────────────
@app.post("/policies/build")
async def build_policy_from_nl(
    request: Request,
    _=Depends(_require_master),
):
    """Generate a YAML policy from natural language rule descriptions.

    Body: {"name": "...", "description": "...", "provider": "...",
           "rules": ["agents can read events", "agents cannot delete events"],
           "default_effect": "deny", "rate_limit_per_minute": 60}
    """
    body = await request.json()
    build_request = PolicyBuildRequest(
        name=body.get("name", "custom_policy"),
        description=body.get("description", ""),
        provider=body.get("provider", "google"),
        rules_nl=body.get("rules", []),
        default_effect=body.get("default_effect", "deny"),
        rate_limit_per_minute=body.get("rate_limit_per_minute", 60),
        rate_limit_per_hour=body.get("rate_limit_per_hour", 1000),
    )
    result = build_policy(build_request)
    return {
        "yaml": result.yaml_content,
        "parsed_rules": result.parsed_rules,
        "warnings": result.warnings,
    }


@app.post("/policies/build-and-load")
async def build_and_load_policy(
    request: Request,
    _=Depends(_require_master),
):
    """Generate a YAML policy from natural language and immediately load it.

    Same body as /policies/build.
    """
    body = await request.json()
    build_request = PolicyBuildRequest(
        name=body.get("name", "custom_policy"),
        description=body.get("description", ""),
        provider=body.get("provider", "google"),
        rules_nl=body.get("rules", []),
        default_effect=body.get("default_effect", "deny"),
        rate_limit_per_minute=body.get("rate_limit_per_minute", 60),
        rate_limit_per_hour=body.get("rate_limit_per_hour", 1000),
    )
    result = build_policy(build_request)

    if result.warnings:
        logger.warning(f"Policy build warnings: {result.warnings}")

    # Load into engine
    from .policy import Policy, RateLimitConfig, _validate_policy_schema
    import yaml as _yaml

    policy_data = _yaml.safe_load(result.yaml_content)
    _validate_policy_schema(policy_data, f"{build_request.name}.yaml")

    rl = policy_data.get("rate_limit", {})
    policy_engine._policies[policy_data["name"]] = Policy(
        name=policy_data["name"],
        description=policy_data.get("description", ""),
        rules=policy_data.get("rules", []),
        default_effect=policy_data.get("default_effect", "deny"),
        default_reason=policy_data.get("default_reason", "Denied"),
        rate_limit=RateLimitConfig(
            enabled=rl.get("enabled", True),
            requests_per_minute=rl.get("requests_per_minute", 60),
            requests_per_hour=rl.get("requests_per_hour", 1000),
        ),
    )

    # Also save to disk
    policy_path = Path(settings.policy_dir) / f"{build_request.name}.yaml"
    policy_path.write_text(result.yaml_content, encoding="utf-8")

    return {
        "status": "loaded",
        "policy_name": build_request.name,
        "yaml": result.yaml_content,
        "parsed_rules": result.parsed_rules,
        "warnings": result.warnings,
        "saved_to": str(policy_path),
    }


# ── L3 Escalation (master key required) ──────────────────────────────
@app.get("/l3/escalations")
async def get_l3_escalations(_=Depends(_require_master)):
    """View recent L3 escalation events."""
    return {
        "escalations": l3_manager.recent_escalations,
        "stats": l3_manager.stats,
    }


@app.post("/l3/resolve/{index}")
async def resolve_l3_escalation(
    index: int,
    request: Request,
    _=Depends(_require_master),
):
    """Mark an L3 escalation as resolved."""
    body = await request.json()
    resolution = body.get("resolution", "Resolved by admin")
    if l3_manager.resolve(index, resolution):
        return {"status": "resolved", "index": index}
    raise HTTPException(status_code=404, detail="Escalation not found")


# ── Workflow Engine (master key required) ────────────────────────────
@app.get("/workflow/rules")
async def get_workflow_rules(_=Depends(_require_master)):
    """List all workflow-level authorization rules."""
    return workflow_engine.stats


@app.post("/workflow/rules")
async def add_workflow_rule(
    request: Request,
    _=Depends(_require_master),
):
    """Add a workflow-level rule.

    Body: {"name": "...", "description": "...", "sequence": ["read", "create"],
           "cross_provider": true, "effect": "deny", "reason": "...",
           "window_seconds": 30}
    """
    body = await request.json()
    rule = WorkflowRule(
        name=body.get("name", "custom_rule"),
        description=body.get("description", ""),
        sequence=body.get("sequence", []),
        providers=body.get("providers"),
        cross_provider=body.get("cross_provider", False),
        effect=body.get("effect", "deny"),
        reason=body.get("reason", "Custom workflow rule violation"),
        window_seconds=body.get("window_seconds", 60.0),
    )
    workflow_engine.add_rule(rule)
    return {"status": "added", "rule": rule.name, "sequence": rule.sequence}


@app.get("/workflow/alerts")
async def get_workflow_alerts(_=Depends(_require_master)):
    """View workflow-level alerts (non-blocking detections)."""
    return {"alerts": workflow_engine.alerts}


# ── MCP Auth Proxy ───────────────────────────────────────────────────
_mcp_proxies: dict[str, MCPAuthProxy] = {}


@app.post("/mcp/servers")
async def register_mcp_server(
    request: Request,
    _=Depends(_require_master),
):
    """Register an upstream MCP server and optionally its tool annotations."""
    body = await request.json()
    server_url: str = body.get("url", "")
    server_name: str = body.get("name", server_url)
    tools: list = body.get("tools", [])

    if not server_url:
        raise HTTPException(status_code=400, detail="'url' is required")

    proxy = MCPAuthProxy(
        upstream_url=server_url,
        policy_engine=policy_engine,
        audit_logger=audit_logger,
    )
    if tools:
        proxy.register_tool_annotations(tools)
        # Auto-generate policy from annotations
        policy_data = tools_to_policy(tools, policy_name=f"mcp_{server_name}")
        from .policy import Policy, _validate_policy_schema

        _validate_policy_schema(policy_data, f"mcp_{server_name}")
        policy_engine._policies[policy_data["name"]] = Policy(
            name=policy_data["name"],
            description=policy_data.get("description", ""),
            rules=policy_data.get("rules", []),
            default_effect=policy_data.get("default_effect", "deny"),
            default_reason=policy_data.get("default_reason", "Denied"),
        )
        logger.info(f"Auto-generated policy '{policy_data['name']}' from MCP tools")

    _mcp_proxies[server_name] = proxy
    return {
        "status": "registered",
        "name": server_name,
        "url": server_url,
        "tools_registered": len(tools),
        "auto_policy": f"mcp_{server_name}" if tools else None,
    }


@app.post("/mcp/{server_name}")
async def mcp_proxy_request(request: Request, server_name: str):
    """Forward JSON-RPC requests to a registered MCP server with authorization."""
    agent_key = _extract_agent_key(request)
    agent = agent_store.get_by_api_key(agent_key)
    if agent is None:
        raise HTTPException(status_code=401, detail="Invalid agent key")

    proxy = _mcp_proxies.get(server_name)
    if proxy is None:
        raise HTTPException(
            status_code=404, detail=f"MCP server '{server_name}' not registered"
        )

    body = await request.json()
    policy_name = agent.get("policy", "default")

    result = await proxy.handle_jsonrpc(
        body,
        agent_id=agent["agent_id"],
        agent_name=agent["name"],
        policy_name=policy_name,
        headers={"Authorization": request.headers.get("authorization", "")},
    )
    return result


# ── Proxy Endpoint (agent key required) ──────────────────────────────
@app.api_route(
    "/proxy/{provider}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def proxy_request(request: Request, provider: str, path: str):
    agent_key = _extract_agent_key(request)
    agent = agent_store.get_by_api_key(agent_key)
    if agent is None:
        raise HTTPException(status_code=401, detail="Invalid agent key")
    return await reverse_proxy.handle(request, agent, provider)


# ── Root ─────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "service": "AgentGate",
        "version": "0.3.0",
        "description": "JIT Authorization Proxy for AI Agents",
        "providers": available_providers(),
        "docs": "/docs" if settings.debug else "disabled",
    }
