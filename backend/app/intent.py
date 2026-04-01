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
    "github": [
        (r"/repos/[^/]+/[^/]+/issues/.+/comments", "issue_comment"),
        (r"/repos/[^/]+/[^/]+/issues/.+", "issue"),
        (r"/repos/[^/]+/[^/]+/issues", "issue"),
        (r"/repos/[^/]+/[^/]+/pulls/.+/reviews", "pull_request_review"),
        (r"/repos/[^/]+/[^/]+/pulls/.+", "pull_request"),
        (r"/repos/[^/]+/[^/]+/pulls", "pull_request"),
        (r"/repos/[^/]+/[^/]+/contents/.+", "repository_content"),
        (r"/repos/[^/]+/[^/]+/branches", "branch"),
        (r"/repos/[^/]+/[^/]+/releases", "release"),
        (r"/repos/[^/]+/[^/]+/actions/runs", "workflow_run"),
        (r"/repos/[^/]+/[^/]+/actions/workflows", "workflow"),
        (r"/repos/[^/]+/[^/]+$", "repository"),
        (r"/user/repos", "repository"),
        (r"/orgs/[^/]+/repos", "repository"),
    ],
    "jira": [
        (r"/issue/[^/]+/comment", "issue_comment"),
        (r"/issue/[^/]+/transitions", "issue_transition"),
        (r"/issue/[^/]+/worklog", "worklog"),
        (r"/issue/[^/]+", "issue"),
        (r"/issue$", "issue"),
        (r"/search", "search"),
        (r"/project/[^/]+", "project"),
        (r"/project$", "project"),
        (r"/board/[^/]+/sprint", "sprint"),
        (r"/board/[^/]+", "board"),
    ],
    "notion": [
        (r"/pages/.+/properties/.+", "page_property"),
        (r"/pages/.+", "page"),
        (r"/pages$", "page"),
        (r"/databases/.+/query", "database_query"),
        (r"/databases/.+", "database"),
        (r"/databases$", "database"),
        (r"/blocks/.+/children", "block_children"),
        (r"/blocks/.+", "block"),
        (r"/users/.+", "user"),
        (r"/users$", "user"),
        (r"/search", "search"),
    ],
    "linear": [
        (r"/graphql", "graphql"),
        (r"/issues/.+/comments", "issue_comment"),
        (r"/issues/.+", "issue"),
        (r"/issues$", "issue"),
        (r"/projects/.+", "project"),
        (r"/projects$", "project"),
        (r"/teams/.+", "team"),
        (r"/cycles/.+", "cycle"),
    ],
    "hubspot": [
        (r"/crm/v3/objects/contacts/.+", "contact"),
        (r"/crm/v3/objects/contacts", "contact"),
        (r"/crm/v3/objects/companies/.+", "company"),
        (r"/crm/v3/objects/companies", "company"),
        (r"/crm/v3/objects/deals/.+", "deal"),
        (r"/crm/v3/objects/deals", "deal"),
        (r"/crm/v3/objects/tickets/.+", "ticket"),
        (r"/crm/v3/objects/tickets", "ticket"),
        (r"/crm/v3/pipelines/.+", "pipeline"),
        (r"/marketing/v3/emails", "marketing_email"),
    ],
    "salesforce": [
        (r"/sobjects/Account/.+", "account"),
        (r"/sobjects/Account", "account"),
        (r"/sobjects/Contact/.+", "contact"),
        (r"/sobjects/Contact", "contact"),
        (r"/sobjects/Opportunity/.+", "opportunity"),
        (r"/sobjects/Opportunity", "opportunity"),
        (r"/sobjects/Lead/.+", "lead"),
        (r"/sobjects/Lead", "lead"),
        (r"/sobjects/Case/.+", "case"),
        (r"/sobjects/Case", "case"),
        (r"/query", "soql_query"),
        (r"/sobjects/.+", "sobject"),
    ],
    "aws": [
        (r"/lambda/functions/.+/invocations", "lambda_invocation"),
        (r"/lambda/functions/.+", "lambda_function"),
        (r"/s3/.+/.+", "s3_object"),
        (r"/s3/.+", "s3_bucket"),
        (r"/dynamodb", "dynamodb_table"),
        (r"/sqs/.+", "sqs_queue"),
        (r"/sns/.+", "sns_topic"),
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

# GitHub methods where POST is a read (e.g., GraphQL query)
_GITHUB_READ_PATHS = frozenset({"/graphql"})

# Jira/Notion searches via POST are reads
_POST_READ_PATHS: dict[str, frozenset[str]] = {
    "jira": frozenset({"/search"}),
    "notion": frozenset({"/search", "/databases"}),
    "linear": frozenset({"/graphql"}),
}


class IntentAnalyzer:
    """Multi-level intent analysis engine.

    L1: Pattern match (HTTP method → intent type, <1ms)
    L2: Rule-based classification (path patterns → resource type, <5ms)
    L3: Async LLM escalation for ambiguous cases (configurable callback)
    """

    def __init__(self, *, l3_callback=None) -> None:
        """Initialize with optional L3 escalation callback.

        Args:
            l3_callback: Optional async callable(method, path, provider, body, intent_result)
                         that fires asynchronously for ambiguous cases.
                         Does NOT block the authorization decision.
        """
        self._l3_callback = l3_callback

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

        # L2: POST-as-read for other providers (search endpoints, GraphQL)
        if method_upper == "POST":
            read_paths = _POST_READ_PATHS.get(provider, frozenset())
            for read_path in read_paths:
                if normalized_path.startswith(read_path):
                    intent_type = "read"
                    break

        confidence = 0.95 if resource_type != "unknown" else 0.6
        level = "L2" if resource_type != "unknown" else "L1"

        result = IntentResult(
            intent_type=intent_type,
            resource_type=resource_type,
            confidence=confidence,
            analysis_level=level,
        )

        # L3: Async escalation for low-confidence or unknown intents
        if self._l3_callback and confidence < 0.8:
            # Fire-and-forget: does NOT block the deterministic decision
            import asyncio
            asyncio.create_task(
                self._l3_escalate(method_upper, normalized_path, provider, body, result)
            )

        return result

    async def _l3_escalate(
        self,
        method: str,
        path: str,
        provider: str,
        body: bytes | None,
        l2_result: IntentResult,
    ) -> None:
        """Async L3 escalation — fires in background, never blocks authorization."""
        try:
            await self._l3_callback(method, path, provider, body, l2_result)
        except Exception:
            pass  # L3 failure must never affect L1/L2 decision

    @staticmethod
    def _classify_resource(path: str, provider: str) -> str:
        """Match path against known patterns for the provider."""
        patterns = _RESOURCE_PATTERNS.get(provider, [])
        for pattern, resource in patterns:
            if re.match(pattern, path):
                return resource
        return "unknown"
