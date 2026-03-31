"""Intent analyzer — classifies request intent using L1/L2/L3 strategy."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .path_normalize import normalize_path


@dataclass
class IntentResult:
    """Structured result of intent analysis."""

    intent_type: str  # "read", "create", "update", "delete", "query", "unknown"
    resource_type: str  # "calendar_event", "calendar_list", "message", "channel", etc.
    confidence: float  # 0.0 - 1.0
    analysis_level: str  # "L1", "L2", "L3"
    reasoning: str | None = None


# ── L1: HTTP Method → Intent mapping ──────────────────────────────────

_METHOD_INTENT: dict[str, str] = {
    "GET": "read",
    "HEAD": "read",
    "OPTIONS": "read",
    "POST": "create",
    "PUT": "update",
    "PATCH": "update",
    "DELETE": "delete",
}

# ── L2: Path pattern → Resource type mapping (per provider) ───────────

_RESOURCE_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "google": [
        (r"/calendars/.+/events/.+", "calendar_event"),
        (r"/calendars/.+/events", "calendar_event"),
        (r"/users/.+/calendarList", "calendar_list"),
        (r"/freeBusy", "availability"),
        (r"/calendars/.+", "calendar"),
    ],
    "microsoft": [
        (r"/me/calendar/events/.+", "calendar_event"),
        (r"/me/calendar/events", "calendar_event"),
        (r"/me/calendars", "calendar_list"),
        (r"/me/calendar/calendarView", "calendar_view"),
        (r"/me/calendar", "calendar"),
        (r"/me/messages/.+", "mail_message"),
        (r"/me/messages", "mail_message"),
        (r"/me/mailFolders", "mail_folder"),
    ],
    "slack": [
        (r"/conversations\.(list|info|history|members)", "channel"),
        (r"/conversations\.(create|invite|kick|archive|unarchive)", "channel_admin"),
        (r"/chat\.(postMessage|update|delete)", "message"),
        (r"/users\.(list|info|lookupByEmail)", "user"),
        (r"/files\.(upload|list|info|delete)", "file"),
        (r"/reactions\.(add|remove|list|get)", "reaction"),
    ],
}

# Slack methods that are reads despite being POST
_SLACK_READ_METHODS = frozenset(
    {
        "conversations.list",
        "conversations.info",
        "conversations.history",
        "conversations.members",
        "users.list",
        "users.info",
        "users.lookupByEmail",
        "files.list",
        "files.info",
        "reactions.list",
        "reactions.get",
    }
)


class IntentAnalyzer:
    """Multi-level intent analysis engine.

    L1: Pattern match (HTTP method → intent type, <1ms)
    L2: Rule-based classification (path patterns → resource type, <5ms)
    L3: LLM analysis (future — placeholder)
    """

    async def analyze(
        self,
        method: str,
        path: str,
        provider: str,
        body: bytes | None = None,
    ) -> IntentResult:
        """Analyze request intent. Falls back through L1 → L2 → L3."""
        method_upper = method.upper()

        # Normalize path before analysis (prevents obfuscation bypass)
        normalized_path = normalize_path(path)

        # L1: Method-based intent
        intent_type = _METHOD_INTENT.get(method_upper, "unknown")

        # L2: Provider-specific refinement
        resource_type = self._classify_resource(normalized_path, provider)

        # L2: Slack override — many "read" operations use POST
        if provider == "slack" and method_upper == "POST":
            # Extract Slack method name from normalized path
            slack_method = normalized_path.lstrip("/")
            if slack_method in _SLACK_READ_METHODS:
                intent_type = "read"

        confidence = 0.95 if resource_type != "unknown" else 0.6
        level = "L2" if resource_type != "unknown" else "L1"

        return IntentResult(
            intent_type=intent_type,
            resource_type=resource_type,
            confidence=confidence,
            analysis_level=level,
        )

    @staticmethod
    def _classify_resource(path: str, provider: str) -> str:
        """Match path against known patterns for the provider."""
        patterns = _RESOURCE_PATTERNS.get(provider, [])
        for pattern, resource in patterns:
            if re.match(pattern, path):
                return resource
        return "unknown"
