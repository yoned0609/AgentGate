"""AgentGate — JIT Authorization Proxy for AI Agents."""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from .agents import AgentStore
from .audit import AuditLogger
from .config import settings
from .middleware.security import SecurityHeadersMiddleware
from .models import AgentCreate, AgentResponse, AuditLogList, HealthResponse, PolicyInfo
from .policy import PolicyEngine
from .proxy import ReverseProxy

# ── Logging ──────────────────────────────────────────────────────────
_LOG_DIR = Path("logs")
_LOG_DIR.mkdir(exist_ok=True)

logger.remove()
logger.add(sys.stdout, level="DEBUG" if settings.debug else "INFO", format="{time:HH:mm:ss} | {level:<7} | {message}")
logger.add(_LOG_DIR / "agentgate.log", rotation="10 MB", retention="30 days", level="INFO", encoding="utf-8")
logger.add(_LOG_DIR / "agentgate_error.log", rotation="10 MB", retention="90 days", level="ERROR", encoding="utf-8")

# ── Core components ──────────────────────────────────────────────────
policy_engine = PolicyEngine(policy_dir=settings.policy_dir)
audit_logger = AuditLogger(db_path=settings.audit_db_path)
agent_store = AgentStore()
reverse_proxy = ReverseProxy(
    target_base_url=settings.google_calendar_base_url,
    policy_engine=policy_engine,
    audit_logger=audit_logger,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("AgentGate starting up")
    logger.info(f"Policies loaded: {policy_engine.policy_names}")
    logger.info(f"Agents registered: {agent_store.count}")
    logger.info(f"Proxy target: {settings.google_calendar_base_url}")
    yield
    await reverse_proxy.close()
    logger.info("AgentGate shut down")


# ── App ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="AgentGate",
    description="JIT Authorization Proxy for AI Agents",
    version="0.1.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url=None,
    lifespan=lifespan,
)

# Middleware (outermost → innermost)
app.add_middleware(SecurityHeadersMiddleware)
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
        version="0.1.0",
        policy_loaded=len(policy_engine.policy_names) > 0,
        agents_count=agent_store.count,
        audit_db="ok" if audit_ok else "error",
    )


# ── Agent Management (master key required) ───────────────────────────
@app.post("/agents", response_model=AgentResponse)
async def create_agent(body: AgentCreate, _=Depends(_require_master)):
    if body.policy not in policy_engine.policy_names:
        raise HTTPException(status_code=400, detail=f"Unknown policy: {body.policy}. Available: {policy_engine.policy_names}")
    agent = agent_store.create(name=body.name, description=body.description, policy=body.policy)
    return AgentResponse(**agent)


@app.get("/agents", response_model=list[AgentResponse])
async def list_agents(_=Depends(_require_master)):
    return [AgentResponse(**a) for a in agent_store.list_all()]


@app.delete("/agents/{agent_id}")
async def delete_agent(agent_id: str, _=Depends(_require_master)):
    if not agent_store.delete(agent_id):
        raise HTTPException(status_code=404, detail="Agent not found")
    return {"status": "deleted"}


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
@app.get("/audit/logs", response_model=AuditLogList)
async def get_audit_logs(
    agent_id: str | None = None,
    decision: str | None = None,
    limit: int = 50,
    offset: int = 0,
    _=Depends(_require_master),
):
    logs, total = await audit_logger.query(
        agent_id=agent_id, decision=decision, limit=limit, offset=offset
    )
    return AuditLogList(logs=logs, total=total)


# ── Proxy Endpoint (agent key required) ──────────────────────────────
@app.api_route("/proxy/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def proxy_request(request: Request, path: str):
    agent_key = _extract_agent_key(request)
    agent = agent_store.get_by_api_key(agent_key)
    if agent is None:
        raise HTTPException(status_code=401, detail="Invalid agent key")
    return await reverse_proxy.handle(request, agent)


# ── Root ─────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "service": "AgentGate",
        "version": "0.1.0",
        "description": "JIT Authorization Proxy for AI Agents",
        "docs": "/docs" if settings.debug else "disabled",
    }
