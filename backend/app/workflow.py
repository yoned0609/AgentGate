"""Workflow-level authorization — enforce multi-step request chain policies.

Addresses the critical gap identified by MarketDisruptor:
AgentGate authorizes individual requests but has zero understanding of
multi-step agent workflows. This module adds sequence-aware constraints.

Design:
- Tracks per-agent request chains within a sliding time window
- Evaluates workflow rules: "read-then-summarize OK, read-then-forward DENY"
- Deterministic (no LLM) — pure state machine on intent sequences
- Non-blocking: workflow check is O(1) per request
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field

from loguru import logger


@dataclass
class WorkflowStep:
    """A single step in an observed workflow."""

    intent_type: str     # "read", "create", "update", "delete"
    resource_type: str
    provider: str
    timestamp: float = field(default_factory=time.monotonic)


@dataclass
class WorkflowRule:
    """A rule that constrains sequences of intents.

    Example: deny if an agent reads mail then immediately creates a message
    to a different provider (data exfiltration pattern).
    """

    name: str
    description: str
    # Sequence to match: list of intent_type strings
    # e.g., ["read", "create"] means "read anything, then create anything"
    sequence: list[str]
    # Optional: constrain which providers are involved
    providers: list[str] | None = None
    # Optional: require cross-provider (exfiltration detection)
    cross_provider: bool = False
    # Effect when sequence is detected
    effect: str = "deny"  # "deny" | "alert"
    reason: str = "Workflow policy violation"
    # Time window in seconds (how close steps must be to form a chain)
    window_seconds: float = 60.0


@dataclass
class WorkflowDecision:
    """Result of workflow evaluation."""

    allowed: bool
    matched_rule: WorkflowRule | None = None
    reason: str | None = None


# ── Default workflow rules ─────────────────────────────────────────

DEFAULT_WORKFLOW_RULES: list[WorkflowRule] = [
    WorkflowRule(
        name="cross_provider_exfiltration",
        description="Deny read-then-create across different providers (data exfiltration)",
        sequence=["read", "create"],
        cross_provider=True,
        effect="deny",
        reason="Cross-provider data flow detected: read from one provider then create on another",
        window_seconds=30.0,
    ),
    WorkflowRule(
        name="bulk_delete_after_read",
        description="Alert on read-then-delete pattern (data destruction after reconnaissance)",
        sequence=["read", "delete"],
        effect="alert",
        reason="Read-then-delete pattern detected — possible data destruction after reconnaissance",
        window_seconds=60.0,
    ),
    WorkflowRule(
        name="rapid_create_spam",
        description="Deny create-create-create rapid fire (spam/abuse pattern)",
        sequence=["create", "create", "create"],
        effect="deny",
        reason="Rapid sequential create operations detected — possible spam or abuse",
        window_seconds=10.0,
    ),
    WorkflowRule(
        name="delete_after_update",
        description="Alert on update-then-delete (modify-then-destroy pattern)",
        sequence=["update", "delete"],
        effect="alert",
        reason="Update-then-delete pattern detected — data may have been modified before destruction",
        window_seconds=30.0,
    ),
]


class WorkflowEngine:
    """Tracks agent request chains and enforces workflow-level policies.

    Usage:
        engine = WorkflowEngine()
        # On each request, after intent analysis:
        decision = engine.evaluate(agent_id, intent, resource, provider)
        if not decision.allowed:
            # deny the request
        engine.record(agent_id, intent, resource, provider)

    Performance:
        - evaluate(): O(R * S) where R = rules, S = max sequence length (typically <5)
        - record(): O(1)
        - Memory: bounded per agent (max_history per agent)
    """

    def __init__(
        self,
        rules: list[WorkflowRule] | None = None,
        max_history_per_agent: int = 50,
    ) -> None:
        self._rules = rules if rules is not None else list(DEFAULT_WORKFLOW_RULES)
        self._max_history = max_history_per_agent
        # agent_id → recent steps
        self._chains: dict[str, list[WorkflowStep]] = defaultdict(list)
        self._alerts: list[dict] = []

    def evaluate(
        self,
        agent_id: str,
        intent_type: str,
        resource_type: str,
        provider: str,
    ) -> WorkflowDecision:
        """Check if the current request + recent history violates any workflow rule.

        Call BEFORE authorizing the request. Does not record the step.
        """
        chain = self._chains.get(agent_id, [])
        now = time.monotonic()

        for rule in self._rules:
            if self._matches_rule(rule, chain, intent_type, provider, now):
                if rule.effect == "deny":
                    logger.warning(
                        f"Workflow DENY: agent={agent_id} rule={rule.name} "
                        f"reason={rule.reason}"
                    )
                    return WorkflowDecision(
                        allowed=False,
                        matched_rule=rule,
                        reason=rule.reason,
                    )
                elif rule.effect == "alert":
                    alert = {
                        "agent_id": agent_id,
                        "rule": rule.name,
                        "reason": rule.reason,
                        "timestamp": time.time(),
                        "current_intent": intent_type,
                        "provider": provider,
                    }
                    self._alerts.append(alert)
                    logger.info(
                        f"Workflow ALERT: agent={agent_id} rule={rule.name}"
                    )
                    # Alert does not block — just records

        return WorkflowDecision(allowed=True)

    def record(
        self,
        agent_id: str,
        intent_type: str,
        resource_type: str,
        provider: str,
    ) -> None:
        """Record a step in the agent's workflow chain. Call AFTER authorization."""
        chain = self._chains[agent_id]
        chain.append(WorkflowStep(
            intent_type=intent_type,
            resource_type=resource_type,
            provider=provider,
        ))
        # Bound history
        if len(chain) > self._max_history:
            self._chains[agent_id] = chain[-self._max_history:]

    def add_rule(self, rule: WorkflowRule) -> None:
        """Add a workflow rule at runtime."""
        self._rules.append(rule)

    def _matches_rule(
        self,
        rule: WorkflowRule,
        chain: list[WorkflowStep],
        current_intent: str,
        current_provider: str,
        now: float,
    ) -> bool:
        """Check if the chain + current request matches a workflow rule."""
        seq = rule.sequence
        if not seq:
            return False

        # The current request is the last element of the sequence
        if current_intent != seq[-1]:
            return False

        # Need len(seq)-1 prior matching steps in the chain
        needed_prior = seq[:-1]
        if len(needed_prior) > len(chain):
            return False

        # Walk backward through chain to find matching sequence
        matched_steps: list[WorkflowStep] = []
        chain_idx = len(chain) - 1
        seq_idx = len(needed_prior) - 1

        while seq_idx >= 0 and chain_idx >= 0:
            step = chain[chain_idx]
            # Check time window
            if (now - step.timestamp) > rule.window_seconds:
                return False
            if step.intent_type == needed_prior[seq_idx]:
                matched_steps.insert(0, step)
                seq_idx -= 1
            chain_idx -= 1

        if seq_idx >= 0:
            return False  # Didn't find all needed prior steps

        # Provider constraints
        if rule.providers:
            all_providers = [s.provider for s in matched_steps] + [current_provider]
            if not all(p in rule.providers for p in all_providers):
                return False

        # Cross-provider check
        if rule.cross_provider:
            providers_in_chain = {s.provider for s in matched_steps}
            providers_in_chain.add(current_provider)
            if len(providers_in_chain) < 2:
                return False  # All same provider — not cross-provider

        return True

    @property
    def alerts(self) -> list[dict]:
        return list(self._alerts)

    @property
    def stats(self) -> dict:
        return {
            "rules_count": len(self._rules),
            "tracked_agents": len(self._chains),
            "total_alerts": len(self._alerts),
            "rules": [
                {"name": r.name, "sequence": r.sequence, "effect": r.effect}
                for r in self._rules
            ],
        }
