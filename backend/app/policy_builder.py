"""Natural language policy builder — converts English descriptions to YAML policies.

Uses deterministic NLP parsing (not LLM at runtime) to generate policy YAML
from structured natural language descriptions. LLM is for *authoring*, not runtime.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml


@dataclass
class PolicyBuildRequest:
    """Structured request for policy generation."""

    name: str
    description: str
    provider: str
    rules_nl: list[str]  # natural language rule descriptions
    default_effect: str = "deny"
    rate_limit_per_minute: int = 60
    rate_limit_per_hour: int = 1000


@dataclass
class PolicyBuildResult:
    """Result of policy generation."""

    yaml_content: str
    parsed_rules: list[dict]
    warnings: list[str] = field(default_factory=list)


# ── Intent keywords → intent types ───────────────────────────────────

_INTENT_KEYWORDS: dict[str, list[str]] = {
    "read": ["read", "view", "get", "list", "fetch", "query", "search", "browse", "check"],
    "create": ["create", "add", "post", "new", "send", "write", "insert", "submit"],
    "update": ["update", "edit", "modify", "change", "patch", "revise"],
    "delete": ["delete", "remove", "destroy", "drop", "purge", "erase", "cancel"],
}

# ── Resource keywords → resource patterns ─────────────────────────────

_RESOURCE_KEYWORDS: dict[str, dict[str, str]] = {
    "google": {
        "calendar": "/calendars/*",
        "event": "/calendars/*/events",
        "events": "/calendars/*/events",
        "specific event": "/calendars/*/events/*",
        "calendar list": "/users/*/calendarList",
        "free busy": "/freeBusy",
        "availability": "/freeBusy",
    },
    "microsoft": {
        "calendar": "/me/calendar",
        "event": "/me/calendar/events",
        "events": "/me/calendar/events",
        "specific event": "/me/calendar/events/*",
        "message": "/me/messages",
        "messages": "/me/messages",
        "email": "/me/messages",
        "mail": "/me/messages",
        "specific message": "/me/messages/*",
    },
    "slack": {
        "channel": "/conversations.*",
        "channels": "/conversations.*",
        "message": "/chat.*",
        "messages": "/chat.*",
        "user": "/users.*",
        "users": "/users.*",
        "file": "/files.*",
        "files": "/files.*",
    },
    "github": {
        "issue": "/repos/*/*/issues",
        "issues": "/repos/*/*/issues",
        "specific issue": "/repos/*/*/issues/*",
        "pull request": "/repos/*/*/pulls",
        "pull requests": "/repos/*/*/pulls",
        "pr": "/repos/*/*/pulls",
        "prs": "/repos/*/*/pulls",
        "repository": "/repos/*/*",
        "repo": "/repos/*/*",
        "content": "/repos/*/*/contents/**",
        "branch": "/repos/*/*/branches",
        "release": "/repos/*/*/releases",
        "workflow": "/repos/*/*/actions/**",
    },
    "jira": {
        "issue": "/issue",
        "issues": "/issue",
        "specific issue": "/issue/*",
        "project": "/project",
        "projects": "/project",
        "board": "/board",
        "sprint": "/board/*/sprint",
        "comment": "/issue/*/comment",
    },
    "notion": {
        "page": "/pages",
        "pages": "/pages",
        "specific page": "/pages/*",
        "database": "/databases",
        "databases": "/databases",
        "block": "/blocks",
        "blocks": "/blocks",
        "search": "/search",
    },
    "linear": {
        "issue": "/issues",
        "issues": "/issues",
        "project": "/projects",
        "team": "/teams",
        "cycle": "/cycles",
    },
    "hubspot": {
        "contact": "/crm/v3/objects/contacts",
        "contacts": "/crm/v3/objects/contacts",
        "company": "/crm/v3/objects/companies",
        "companies": "/crm/v3/objects/companies",
        "deal": "/crm/v3/objects/deals",
        "deals": "/crm/v3/objects/deals",
        "ticket": "/crm/v3/objects/tickets",
        "tickets": "/crm/v3/objects/tickets",
    },
    "salesforce": {
        "account": "/sobjects/Account",
        "contact": "/sobjects/Contact",
        "opportunity": "/sobjects/Opportunity",
        "lead": "/sobjects/Lead",
        "case": "/sobjects/Case",
    },
    "aws": {
        "lambda": "/lambda/functions/**",
        "s3": "/s3/**",
        "dynamodb": "/dynamodb",
        "sqs": "/sqs/**",
    },
}

# ── Effect keywords ───────────────────────────────────────────────────

_ALLOW_KEYWORDS = {"can", "allow", "permit", "enable", "may", "should be able to"}
_DENY_KEYWORDS = {"cannot", "can't", "deny", "block", "prevent", "forbid", "must not", "should not", "disallow"}

# ── Methods mapping ───────────────────────────────────────────────────

_INTENT_TO_METHODS: dict[str, list[str]] = {
    "read": ["GET", "HEAD"],
    "create": ["POST"],
    "update": ["PUT", "PATCH"],
    "delete": ["DELETE"],
}


def build_policy(request: PolicyBuildRequest) -> PolicyBuildResult:
    """Parse natural language rules and generate a YAML policy."""
    rules: list[dict] = []
    warnings: list[str] = []

    for nl_rule in request.rules_nl:
        parsed = _parse_rule(nl_rule, request.provider, warnings)
        if parsed:
            rules.append(parsed)

    policy_data = {
        "name": request.name,
        "description": request.description,
        "default_effect": request.default_effect,
        "default_reason": f"Denied by {request.name} policy",
        "rate_limit": {
            "enabled": True,
            "requests_per_minute": request.rate_limit_per_minute,
            "requests_per_hour": request.rate_limit_per_hour,
        },
        "rules": rules,
    }

    yaml_content = yaml.dump(policy_data, default_flow_style=False, allow_unicode=True, sort_keys=False)

    return PolicyBuildResult(
        yaml_content=yaml_content,
        parsed_rules=rules,
        warnings=warnings,
    )


def _parse_rule(nl: str, provider: str, warnings: list[str]) -> dict | None:
    """Parse a single natural language rule description into a policy rule dict."""
    nl_lower = nl.lower().strip()

    # Detect effect
    effect = _detect_effect(nl_lower)

    # Detect intents
    intents = _detect_intents(nl_lower)

    # Detect resource
    resource = _detect_resource(nl_lower, provider)

    if not intents and not resource:
        warnings.append(f"Could not parse rule: '{nl}'. Skipping.")
        return None

    # Build methods from intents
    methods: list[str] = []
    for intent in intents:
        methods.extend(_INTENT_TO_METHODS.get(intent, []))

    rule: dict = {"effect": effect}

    if resource:
        rule["resource"] = resource
    if methods:
        rule["methods"] = sorted(set(methods))
    if intents:
        rule["intent"] = intents if len(intents) > 1 else intents[0]
    rule["reason"] = nl.strip()

    return rule


def _detect_effect(text: str) -> str:
    """Detect allow/deny from natural language."""
    for keyword in _DENY_KEYWORDS:
        if keyword in text:
            return "deny"
    for keyword in _ALLOW_KEYWORDS:
        if keyword in text:
            return "allow"
    return "allow"  # default to allow if ambiguous


def _detect_intents(text: str) -> list[str]:
    """Extract intent types from natural language."""
    found: list[str] = []
    for intent_type, keywords in _INTENT_KEYWORDS.items():
        for keyword in keywords:
            # Match whole word
            if re.search(rf"\b{re.escape(keyword)}\b", text):
                if intent_type not in found:
                    found.append(intent_type)
                break
    return found


def _detect_resource(text: str, provider: str) -> str | None:
    """Extract resource pattern from natural language."""
    resource_map = _RESOURCE_KEYWORDS.get(provider, {})
    # Try longest match first
    for keyword in sorted(resource_map.keys(), key=len, reverse=True):
        if keyword in text:
            return resource_map[keyword]
    return None
