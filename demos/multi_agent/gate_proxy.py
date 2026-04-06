"""
AgentGate Multi-Agent Proxy
============================
Core hub that relays all inter-agent communication,
enforcing policy checks, PII masking, and trace logging.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class Decision(str, Enum):
    ALLOW = "allow"
    MASK = "mask"
    BLOCK = "block"


class RelayRequest(BaseModel):
    from_agent: str
    to_agent: str
    payload: str
    metadata: dict[str, Any] = {}


class RelayResponse(BaseModel):
    request_id: str
    decision: Decision
    original_payload: str | None = None
    delivered_payload: str | None = None
    violations: list[dict[str, str]] = []
    trace: dict[str, Any] = {}


class AgentRegister(BaseModel):
    agent_id: str
    role: str


@dataclass
class TraceEntry:
    request_id: str
    timestamp: float
    from_agent: str
    to_agent: str
    decision: str
    payload_preview: str
    violations: list[dict[str, str]]


# ---------------------------------------------------------------------------
# Policy Engine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """Inspects and enforces YAML-based communication policies."""

    def __init__(self, policy_path: str | Path):
        self.policy_path = Path(policy_path)
        self._load()

    def _load(self):
        with open(self.policy_path) as f:
            self.config = yaml.safe_load(f)
        self._compile_patterns()

    def _compile_patterns(self):
        self.pii_patterns: list[tuple[re.Pattern, str]] = []
        self.forbidden_patterns: list[tuple[re.Pattern, str]] = []

        for entry in self.config.get("blocked_patterns", {}).get("pii", []):
            self.pii_patterns.append(
                (re.compile(entry["pattern"], re.IGNORECASE), entry["label"])
            )
        for entry in self.config.get("blocked_patterns", {}).get("forbidden_words", []):
            self.forbidden_patterns.append(
                (re.compile(entry["pattern"], re.IGNORECASE), entry["label"])
            )

        self.masking_config = self.config.get("masking", {})
        self.agent_permissions = self.config.get("agent_permissions", {})

    def check_routing(self, from_agent: str, to_agent: str) -> str | None:
        perms = self.agent_permissions.get(from_agent)
        if perms is None:
            return f"Unregistered agent: {from_agent}"
        if to_agent not in perms.get("can_send_to", []):
            return f"Routing denied: {from_agent} -> {to_agent}"
        return None

    def check_message_size(self, from_agent: str, payload: str) -> str | None:
        perms = self.agent_permissions.get(from_agent, {})
        max_size = perms.get("max_message_size", 10000)
        if len(payload) > max_size:
            return f"Message size exceeded: {len(payload)} > {max_size}"
        return None

    def scan_payload(self, payload: str) -> tuple[Decision, str, list[dict[str, str]]]:
        violations: list[dict[str, str]] = []
        processed = payload

        for pattern, label in self.forbidden_patterns:
            if pattern.search(processed):
                violations.append({"type": "forbidden_word", "label": label})

        if violations and self.masking_config.get("forbidden_words") == "block":
            return Decision.BLOCK, "", violations

        pii_violations: list[dict[str, str]] = []
        for pattern, label in self.pii_patterns:
            if pattern.search(processed):
                pii_violations.append({"type": "pii", "label": label})
                processed = pattern.sub("***", processed)

        if pii_violations:
            violations.extend(pii_violations)
            if self.masking_config.get("pii") == "block":
                return Decision.BLOCK, "", violations
            return Decision.MASK, processed, violations

        return Decision.ALLOW, processed, violations


# ---------------------------------------------------------------------------
# AgentGate Proxy
# ---------------------------------------------------------------------------

@dataclass
class AgentGateProxy:
    """Security & governance hub for inter-agent communication."""

    policy_engine: PolicyEngine
    agents: dict[str, dict[str, str]] = field(default_factory=dict)
    trace_log: list[TraceEntry] = field(default_factory=list)
    _callbacks: dict[str, Any] = field(default_factory=dict)

    def register_agent(self, agent_id: str, role: str):
        self.agents[agent_id] = {"role": role, "registered_at": time.time()}
        self._log_system(f"Agent registered: {agent_id} (role={role})")

    def set_callback(self, agent_id: str, callback):
        self._callbacks[agent_id] = callback

    def relay(self, from_agent: str, to_agent: str, payload: str,
              metadata: dict | None = None) -> RelayResponse:
        request_id = f"req_{uuid.uuid4().hex[:12]}"
        metadata = metadata or {}

        if from_agent not in self.agents:
            raise ValueError(f"Unknown source agent: {from_agent}")
        if to_agent not in self.agents:
            raise ValueError(f"Unknown target agent: {to_agent}")

        # Routing check
        routing_error = self.policy_engine.check_routing(from_agent, to_agent)
        if routing_error:
            entry = self._record_trace(
                request_id, from_agent, to_agent, "BLOCK",
                payload[:80], [{"type": "routing", "label": routing_error}]
            )
            return RelayResponse(
                request_id=request_id, decision=Decision.BLOCK,
                original_payload=payload,
                violations=[{"type": "routing", "label": routing_error}],
                trace=self._trace_to_dict(entry),
            )

        # Size check
        size_error = self.policy_engine.check_message_size(from_agent, payload)
        if size_error:
            entry = self._record_trace(
                request_id, from_agent, to_agent, "BLOCK",
                payload[:80], [{"type": "size", "label": size_error}]
            )
            return RelayResponse(
                request_id=request_id, decision=Decision.BLOCK,
                original_payload=payload,
                violations=[{"type": "size", "label": size_error}],
                trace=self._trace_to_dict(entry),
            )

        # Payload scan
        decision, processed_payload, violations = self.policy_engine.scan_payload(payload)

        entry = self._record_trace(
            request_id, from_agent, to_agent, decision.value.upper(),
            (processed_payload or payload)[:80], violations,
        )

        # Deliver
        if decision != Decision.BLOCK and to_agent in self._callbacks:
            self._callbacks[to_agent](from_agent, processed_payload, metadata)

        return RelayResponse(
            request_id=request_id, decision=decision,
            original_payload=payload if decision == Decision.MASK else None,
            delivered_payload=processed_payload if decision != Decision.BLOCK else None,
            violations=violations,
            trace=self._trace_to_dict(entry),
        )

    def get_trace_log(self) -> list[dict]:
        return [self._trace_to_dict(e) for e in self.trace_log]

    def _record_trace(self, request_id, from_agent, to_agent, decision,
                      preview, violations) -> TraceEntry:
        entry = TraceEntry(
            request_id=request_id, timestamp=time.time(),
            from_agent=from_agent, to_agent=to_agent,
            decision=decision, payload_preview=preview,
            violations=violations,
        )
        self.trace_log.append(entry)
        self._log_traffic(entry)
        return entry

    def _trace_to_dict(self, entry: TraceEntry) -> dict:
        return {
            "request_id": entry.request_id,
            "timestamp": entry.timestamp,
            "from": entry.from_agent,
            "to": entry.to_agent,
            "decision": entry.decision,
            "payload_preview": entry.payload_preview,
            "violations": entry.violations,
        }

    def _log_system(self, msg: str):
        print(f"  \033[90m[AgentGate]\033[0m {msg}")

    def _log_traffic(self, entry: TraceEntry):
        color = {"ALLOW": "\033[32m", "MASK": "\033[33m", "BLOCK": "\033[31m"}
        reset = "\033[0m"
        c = color.get(entry.decision, "")
        status = f"{c}{entry.decision}{reset}"
        print(
            f"  \033[90m[AgentGate]\033[0m "
            f"{entry.from_agent} -> {entry.to_agent}  "
            f"[{status}]  "
            f"id={entry.request_id}  "
            f'preview="{entry.payload_preview[:50]}..."'
        )
        for v in entry.violations:
            print(f"           ! {v['type']}: {v['label']}")


# ---------------------------------------------------------------------------
# FastAPI HTTP Layer
# ---------------------------------------------------------------------------

def create_app(policy_path: str = "policies.yaml") -> tuple[FastAPI, AgentGateProxy]:
    policy_engine = PolicyEngine(policy_path)
    proxy = AgentGateProxy(policy_engine=policy_engine)

    app = FastAPI(
        title="AgentGate Multi-Agent Proxy",
        description="Security & governance hub for multi-agent communication",
        version="0.1.0",
    )

    @app.post("/agents/register")
    def register(req: AgentRegister):
        proxy.register_agent(req.agent_id, req.role)
        return {"status": "registered", "agent_id": req.agent_id}

    @app.post("/relay", response_model=RelayResponse)
    def relay(req: RelayRequest):
        try:
            return proxy.relay(
                req.from_agent, req.to_agent, req.payload, req.metadata
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/trace")
    def trace():
        return {"entries": proxy.get_trace_log()}

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "agents": list(proxy.agents.keys()),
            "trace_count": len(proxy.trace_log),
        }

    return app, proxy
