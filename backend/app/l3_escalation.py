"""L3 Escalation — async webhook notification for low-confidence intents.

Design principles:
- NEVER blocks L1/L2 deterministic authorization
- Fire-and-forget: webhook delivery failure is non-fatal
- Delivers structured payload for human review or external LLM analysis
- Integrates with existing WebhookNotifier infrastructure
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from loguru import logger

from .webhook import WebhookNotifier


@dataclass
class L3EscalationRecord:
    """Record of an L3 escalation event."""

    method: str
    path: str
    provider: str
    l2_intent: str
    l2_resource: str
    l2_confidence: float
    timestamp: float = field(default_factory=time.time)
    resolved: bool = False
    resolution: str | None = None


class L3EscalationManager:
    """Manages async L3 escalation to webhooks for human/LLM review.

    Integration:
        analyzer = IntentAnalyzer(l3_callback=l3_manager.escalate)

    When a low-confidence intent is detected, this fires a webhook
    with full context for external review. The authorization decision
    is NOT affected — L1/L2 result stands regardless.
    """

    def __init__(self, webhook_notifier: WebhookNotifier) -> None:
        self._webhook = webhook_notifier
        self._history: list[L3EscalationRecord] = []
        self._max_history: int = 1000

    async def escalate(
        self,
        method: str,
        path: str,
        provider: str,
        body: bytes | None,
        l2_result: Any,
    ) -> None:
        """Async L3 callback — fires webhook for low-confidence intents.

        This is the function passed as `l3_callback` to IntentAnalyzer.
        """
        intent_type = getattr(l2_result, "intent_type", "unknown")
        resource_type = getattr(l2_result, "resource_type", "unknown")
        confidence = getattr(l2_result, "confidence", 0.0)

        record = L3EscalationRecord(
            method=method,
            path=path,
            provider=provider,
            l2_intent=intent_type,
            l2_resource=resource_type,
            l2_confidence=confidence,
        )

        # Store in bounded history
        self._history.append(record)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        logger.info(
            f"L3 escalation: {method} {provider}:{path} "
            f"intent={intent_type} confidence={confidence:.2f}"
        )

        # Fire webhook notification
        payload = {
            "event": "l3_escalation",
            "method": method,
            "path": path,
            "provider": provider,
            "l2_analysis": {
                "intent_type": intent_type,
                "resource_type": resource_type,
                "confidence": confidence,
            },
            "action_required": (
                "Low-confidence intent detected. "
                "L1/L2 decision was applied but may need human review. "
                "No action needed if the current policy correctly handles this case."
            ),
            "body_preview": (
                body[:200].decode("utf-8", errors="replace") if body else None
            ),
        }

        try:
            await self._webhook.notify("l3_escalation", payload)
        except Exception as e:
            # Webhook failure must never propagate
            logger.warning(f"L3 webhook delivery failed (non-fatal): {e}")

    @property
    def pending_count(self) -> int:
        return sum(1 for r in self._history if not r.resolved)

    @property
    def recent_escalations(self) -> list[dict]:
        """Return last 50 escalation records."""
        return [
            {
                "method": r.method,
                "path": r.path,
                "provider": r.provider,
                "l2_intent": r.l2_intent,
                "l2_confidence": r.l2_confidence,
                "timestamp": r.timestamp,
                "resolved": r.resolved,
            }
            for r in self._history[-50:]
        ]

    def resolve(self, index: int, resolution: str) -> bool:
        """Mark an escalation as resolved with a resolution note."""
        if 0 <= index < len(self._history):
            self._history[index].resolved = True
            self._history[index].resolution = resolution
            return True
        return False

    @property
    def stats(self) -> dict:
        total = len(self._history)
        resolved = sum(1 for r in self._history if r.resolved)
        return {
            "total_escalations": total,
            "resolved": resolved,
            "pending": total - resolved,
        }
