"""Pydantic models for the AgentGate SDK."""

from __future__ import annotations

from pydantic import BaseModel


# ── Agent Models ─────────────────────────────────────────────────────


class AgentCreateParams(BaseModel):
    """Parameters for creating an agent."""

    name: str
    description: str = ""
    policy: str = "default"
    provider: str = "google"


class Agent(BaseModel):
    """An agent registered with AgentGate."""

    agent_id: str
    name: str
    description: str
    api_key: str
    policy: str
    provider: str
    created_at: str
    request_count: int = 0
    deny_count: int = 0
    last_request_at: str | None = None


class AgentStats(BaseModel):
    """Usage statistics for an agent."""

    agent_id: str
    name: str
    request_count: int
    deny_count: int
    deny_rate: float
    last_request_at: str | None = None


# ── Audit Models ─────────────────────────────────────────────────────


class AuditLogEntry(BaseModel):
    """A single audit log entry."""

    id: int
    timestamp: str
    agent_id: str
    agent_name: str
    method: str
    path: str
    provider: str = ""
    decision: str
    deny_reason: str | None = None
    intent: str = ""
    intent_confidence: float = 0
    status_code: int | None = None
    latency_ms: float
    request_id: str


class AuditLogList(BaseModel):
    """Paginated list of audit log entries."""

    logs: list[AuditLogEntry]
    total: int


class AuditExport(BaseModel):
    """Export result from the audit endpoint."""

    logs: list[dict]
    count: int


class AuditPurgeResult(BaseModel):
    """Result of an audit purge operation."""

    purged: int
    retention_days: int


# ── Policy Models ────────────────────────────────────────────────────


class PolicyInfo(BaseModel):
    """Information about a loaded policy."""

    name: str
    rules: list[dict]


# ── Webhook / Alert Models ───────────────────────────────────────────


class WebhookCreateParams(BaseModel):
    """Parameters for registering a webhook."""

    url: str
    events: list[str] = ["deny", "rate_limited"]
    headers: dict[str, str] = {}


class AlertThresholdCreateParams(BaseModel):
    """Parameters for registering an alert threshold."""

    event: str = "deny"
    count: int = 10
    window_seconds: int = 300
    agent_id: str | None = None


# ── MCP Models ───────────────────────────────────────────────────────


class MCPServerCreateParams(BaseModel):
    """Parameters for registering an MCP server."""

    url: str
    name: str = ""
    tools: list[dict] = []


# ── Health / Discovery ───────────────────────────────────────────────


class HealthStatus(BaseModel):
    """Health check response."""

    status: str
    version: str
    providers: list[str]
    policy_loaded: bool
    agents_count: int
    audit_db: str
