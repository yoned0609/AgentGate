"""Pydantic models for AgentGate API."""

from __future__ import annotations

from pydantic import BaseModel


class AgentCreate(BaseModel):
    name: str
    description: str = ""
    policy: str = "default"
    provider: str = "google"


class AgentResponse(BaseModel):
    agent_id: str
    name: str
    description: str
    api_key: str
    policy: str
    provider: str
    created_at: str


class AuditLogEntry(BaseModel):
    id: int
    timestamp: str
    agent_id: str
    agent_name: str
    method: str
    path: str
    provider: str = ""
    decision: str  # "allow" | "deny" | "error"
    deny_reason: str | None = None
    intent: str = ""
    intent_confidence: float = 0
    status_code: int | None = None
    latency_ms: float
    request_id: str


class AuditLogList(BaseModel):
    logs: list[AuditLogEntry]
    total: int


class PolicyInfo(BaseModel):
    name: str
    rules: list[dict]


class HealthResponse(BaseModel):
    status: str
    version: str
    providers: list[str]
    policy_loaded: bool
    agents_count: int
    audit_db: str
