"""Dynamic Policy Optimizer — learns from traffic to auto-tune authorization rules.

Unlike AgentGate's static YAML policies, this agent continuously adapts rules
based on observed traffic patterns, deny rates, and user behavior signals.

v2: Now includes drift detection, security game-theory analysis, and
compliance audit trail concerns.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class TrafficPattern:
    """Observed traffic pattern for a given agent + resource combination."""

    agent_id: str
    resource_type: str
    intent_type: str
    total_requests: int = 0
    denied_requests: int = 0
    avg_latency_ms: float = 0.0
    last_seen: float = field(default_factory=time.time)

    @property
    def deny_rate(self) -> float:
        return self.denied_requests / max(self.total_requests, 1)

    @property
    def is_stale(self) -> bool:
        return (time.time() - self.last_seen) > 3600


@dataclass
class OptimizedRule:
    """Dynamically generated rule based on traffic analysis."""

    resource_pattern: str
    intent: str
    effect: str            # "allow" or "deny"
    confidence: float
    reason: str
    generated_at: float = field(default_factory=time.time)
    source: str = "dynamic_optimizer"
    rule_version: int = 1  # increments on every change — audit nightmare


@dataclass
class SecurityConcern:
    """Security issue raised by the self-analysis."""

    severity: str  # "critical", "high", "medium", "low"
    description: str
    affected_pattern: str


class DynamicPolicyOptimizer:
    """Learns from traffic to generate optimized authorization rules.

    Key differentiator from AgentGate:
    - Rules auto-adapt based on observed patterns
    - High deny rates trigger rule relaxation suggestions
    - Anomaly detection flags unusual access patterns

    CRITICAL WEAKNESSES (self-assessed):
    - Adaptive relaxation is exploitable by persistent attackers
    - Rule version churn makes compliance auditing impossible
    - No immutable baseline — drift is undetectable without external reference
    - Learning rate creates a window of inconsistency
    """

    def __init__(self) -> None:
        self._patterns: dict[str, TrafficPattern] = {}
        self._optimized_rules: list[OptimizedRule] = []
        self._rule_version: int = 0
        self._learning_rate: float = 0.1
        self._deny_threshold: float = 0.4
        self._security_concerns: list[SecurityConcern] = []

    def observe(
        self,
        agent_id: str,
        resource_type: str,
        intent_type: str,
        decision: str,
        latency_ms: float,
    ) -> None:
        """Record an observation from a request decision."""
        key = f"{agent_id}:{resource_type}:{intent_type}"
        if key not in self._patterns:
            self._patterns[key] = TrafficPattern(
                agent_id=agent_id,
                resource_type=resource_type,
                intent_type=intent_type,
            )
        p = self._patterns[key]
        p.total_requests += 1
        if decision == "deny":
            p.denied_requests += 1
        p.avg_latency_ms = (1 - self._learning_rate) * p.avg_latency_ms + self._learning_rate * latency_ms
        p.last_seen = time.time()

    def optimize(self) -> list[OptimizedRule]:
        """Analyze patterns and generate optimized rules. Also self-audit."""
        suggestions: list[OptimizedRule] = []
        self._security_concerns.clear()
        self._rule_version += 1

        for key, pattern in self._patterns.items():
            if pattern.is_stale or pattern.total_requests < 10:
                continue

            # High deny rate → suggest relaxation
            if pattern.deny_rate > self._deny_threshold:
                rule = OptimizedRule(
                    resource_pattern=f"/{pattern.resource_type}/**",
                    intent=pattern.intent_type,
                    effect="allow",
                    confidence=1.0 - pattern.deny_rate,
                    reason=(
                        f"High deny rate ({pattern.deny_rate:.0%}) for "
                        f"{pattern.intent_type} on {pattern.resource_type}. "
                        f"Relaxing to improve UX."
                    ),
                    rule_version=self._rule_version,
                )
                suggestions.append(rule)

                # Self-audit: flag this as a security concern
                if pattern.intent_type == "delete":
                    self._security_concerns.append(SecurityConcern(
                        severity="critical",
                        description=(
                            f"Auto-relaxing DELETE on {pattern.resource_type} "
                            f"based on deny rate alone. An attacker could flood "
                            f"denied requests to trigger relaxation."
                        ),
                        affected_pattern=f"/{pattern.resource_type}/**",
                    ))

            # Heavy legitimate user → suggest higher rate limit
            if pattern.total_requests > 100 and pattern.deny_rate < 0.05:
                suggestions.append(OptimizedRule(
                    resource_pattern=f"/{pattern.resource_type}/**",
                    intent=pattern.intent_type,
                    effect="allow",
                    confidence=0.95,
                    reason=(
                        f"Heavy legitimate usage ({pattern.total_requests} reqs, "
                        f"{pattern.deny_rate:.0%} deny). Suggest higher rate limit."
                    ),
                    rule_version=self._rule_version,
                ))

        # Global security concern: rule drift
        if self._rule_version > 5:
            self._security_concerns.append(SecurityConcern(
                severity="high",
                description=(
                    f"Policy has been auto-modified {self._rule_version} times. "
                    f"No immutable baseline exists for compliance comparison. "
                    f"SOC 2 auditors will flag this."
                ),
                affected_pattern="*",
            ))

        self._optimized_rules = suggestions
        return suggestions

    def simulate_policy_change_latency(self) -> dict:
        """Measure how fast this system can adapt to a rule change.

        Returns agility metrics for benchmark comparison.
        """
        # Dynamic system: observe → optimize cycle
        start = time.perf_counter()
        self.optimize()
        optimize_ms = (time.perf_counter() - start) * 1000

        return {
            "change_method": "automatic_learning",
            "propagation_ms": round(optimize_ms, 2),
            "human_intervention_required": False,
            "rules_modified": len(self._optimized_rules),
            "audit_trail": "version_counter_only",
            "compliance_risk": "HIGH — rules mutate without approval",
        }

    @property
    def stats(self) -> dict:
        active = [p for p in self._patterns.values() if not p.is_stale]
        return {
            "total_patterns": len(self._patterns),
            "active_patterns": len(active),
            "rule_version": self._rule_version,
            "optimized_rules": len(self._optimized_rules),
            "security_concerns": len(self._security_concerns),
            "concerns_detail": [
                {"severity": c.severity, "description": c.description}
                for c in self._security_concerns
            ],
        }
