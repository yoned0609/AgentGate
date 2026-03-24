"""Pydantic models for AgentGate API."""

from __future__ import annotations

from pydantic import BaseModel


class AgentCreate(BaseModel):
    name: str
    description: str = ""
    policy: str = "default"


class AgentResponse(BaseModel):
    agent_id: str
    name: str
    description: str
    api_key: str
    policy: str
    created_at: str


class AuditLogEntry(BaseModel):
    id: int
    timestamp: str
    agent_id: str
    agent_name: str
    method: str
    path: str
    decision: str  # "allow" | "deny"
    deny_reason: str | None = None
    status_code: int | None = None
    latency_ms: float
    request_id: str


class AuditLogList(BaseModel):
    logs: list[AuditLogEntry]
    total: int


class PolicyInfo(BaseModel):
    name: str
    rules: list[dict]


class ProxyDenied(BaseModel):
    error: str
    reason: str
    request_id: str
    policy: str


class HealthResponse(BaseModel):
    status: str
    version: str
    policy_loaded: bool
    agents_count: int
    audit_db: str
