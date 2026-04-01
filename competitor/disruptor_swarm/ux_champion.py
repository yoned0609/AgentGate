"""UX Champion — transforms latency into perceived value through rich responses.

Strategy: Reframe AgentGate's 5ms speed as "shallow analysis" and position
this system's 500ms+ latency as "deep understanding" with rich metadata.

v2: Now includes honest self-critique — quantifies the UX cost of latency
for real-time agent workflows where every millisecond compounds.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class RichAuthResponse:
    """Enhanced response that turns delay into perceived value."""

    decision: str
    reasoning_summary: str
    confidence_score: float
    analysis_depth: str           # "surface" | "semantic" | "deep_context"
    context_metadata: dict
    alternative_actions: list[str]
    risk_assessment: dict
    processing_time_ms: float
    token_cost_usd: float

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "analysis": {
                "summary": self.reasoning_summary,
                "confidence": self.confidence_score,
                "depth": self.analysis_depth,
                "risk": self.risk_assessment,
            },
            "guidance": {
                "alternatives": self.alternative_actions,
            },
            "metadata": {
                "processing_time_ms": round(self.processing_time_ms, 1),
                "token_cost_usd": round(self.token_cost_usd, 6),
                **self.context_metadata,
            },
        }


_RISK_PRESETS = {
    "low":      {"level": "low",      "color": "#22c55e", "icon": "shield-check"},
    "medium":   {"level": "medium",   "color": "#f59e0b", "icon": "shield-alert"},
    "high":     {"level": "high",     "color": "#ef4444", "icon": "shield-x"},
    "critical": {"level": "critical", "color": "#dc2626", "icon": "alert-triangle"},
}

_ALTERNATIVES = {
    "delete": [
        "Read the resource first with GET before deciding to delete",
        "Consider archiving instead of permanent deletion",
        "Request elevated permissions from your admin",
    ],
    "create": [
        "Check existing resources first with GET",
        "Use draft/sandbox mode if available",
        "Request write permissions from your admin",
    ],
    "update": [
        "Read current state first to understand changes",
        "Use PATCH for partial updates instead of PUT",
        "Back up shared resources before modifying",
    ],
    "read": [
        "Narrow query scope to reduce data exposure",
        "Use field selectors to request only needed data",
    ],
}


class UXChampion:
    """Transforms authorization decisions into rich, developer-friendly responses.

    Competitive narrative against AgentGate:
    - AgentGate: {"error": "access_denied", "reason": "...", "suggestion": "..."}
    - Disruptor: reasoning chain + risk viz + alternatives + cost transparency
    """

    def __init__(self) -> None:
        self._response_count = 0
        self._total_processing_ms = 0.0

    def enrich_response(
        self,
        decision: str,
        intent_type: str,
        resource_type: str,
        confidence: float,
        reasoning_chain: list[str],
        risk_level: str,
        latency_ms: float,
        token_cost: float,
    ) -> RichAuthResponse:
        self._response_count += 1
        self._total_processing_ms += latency_ms

        reasoning_summary = " → ".join(reasoning_chain) if reasoning_chain else "Standard evaluation"

        depth = "deep_context" if len(reasoning_chain) >= 4 else (
            "semantic" if len(reasoning_chain) >= 2 else "surface"
        )

        return RichAuthResponse(
            decision=decision,
            reasoning_summary=reasoning_summary,
            confidence_score=confidence,
            analysis_depth=depth,
            context_metadata={
                "intent_type": intent_type,
                "resource_type": resource_type,
                "reasoning_steps": len(reasoning_chain),
            },
            alternative_actions=_ALTERNATIVES.get(intent_type, ["Contact your admin"]),
            risk_assessment=_RISK_PRESETS.get(risk_level, _RISK_PRESETS["medium"]),
            processing_time_ms=latency_ms,
            token_cost_usd=token_cost,
        )

    def generate_comparison_narrative(
        self,
        our_response: RichAuthResponse,
        agentgate_latency_ms: float = 3.0,
    ) -> dict:
        """Generate competitive comparison. Includes honest self-critique."""
        ratio = our_response.processing_time_ms / max(agentgate_latency_ms, 0.01)

        return {
            "marketing_spin": {
                "headline": f"Deep analysis in {our_response.processing_time_ms:.0f}ms vs surface scan in {agentgate_latency_ms:.1f}ms",
                "value_prop": f"{len(our_response.alternative_actions)} actionable alternatives provided",
            },
            "honest_reality": {
                "latency_multiple": f"{ratio:.0f}x slower",
                "compound_effect": (
                    f"In a 5-step agent workflow, {our_response.processing_time_ms:.0f}ms × 5 = "
                    f"{our_response.processing_time_ms * 5:.0f}ms total auth overhead. "
                    f"AgentGate: {agentgate_latency_ms * 5:.0f}ms. "
                    f"User-perceptible delay at 3+ steps."
                ),
                "cost_at_scale": (
                    f"${our_response.token_cost_usd:.4f}/req × 1M req/day = "
                    f"${our_response.token_cost_usd * 1_000_000:.0f}/day. "
                    f"AgentGate: $0/day."
                ),
            },
        }

    @property
    def stats(self) -> dict:
        return {
            "total_responses": self._response_count,
            "avg_processing_ms": round(
                self._total_processing_ms / max(self._response_count, 1), 1
            ),
        }
