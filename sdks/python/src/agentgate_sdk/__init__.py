"""AgentGate Python SDK — JIT Authorization Proxy for AI Agents."""

from .client import AgentGateClient, AsyncAgentGateClient
from .exceptions import (
    AgentGateError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)
from .models import (
    Agent,
    AgentCreateParams,
    AgentStats,
    AlertThresholdCreateParams,
    AuditExport,
    AuditLogEntry,
    AuditLogList,
    AuditPurgeResult,
    HealthStatus,
    MCPServerCreateParams,
    PolicyInfo,
    WebhookCreateParams,
)

__all__ = [
    # Clients
    "AgentGateClient",
    "AsyncAgentGateClient",
    # Exceptions
    "AgentGateError",
    "AuthenticationError",
    "AuthorizationError",
    "NotFoundError",
    "RateLimitError",
    "ServerError",
    "ValidationError",
    # Models
    "Agent",
    "AgentCreateParams",
    "AgentStats",
    "AlertThresholdCreateParams",
    "AuditExport",
    "AuditLogEntry",
    "AuditLogList",
    "AuditPurgeResult",
    "HealthStatus",
    "MCPServerCreateParams",
    "PolicyInfo",
    "WebhookCreateParams",
]

__version__ = "0.1.0"
