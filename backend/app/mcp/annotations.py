"""MCP tool annotation → policy rule converter.

Converts MCP tool annotations (readOnlyHint, destructiveHint, etc.)
into AgentGate policy rules that the existing PolicyEngine can evaluate.
"""

from __future__ import annotations

from typing import Any


# MCP annotation keys → intent type mapping
_ANNOTATION_INTENT_MAP = {
    "readOnlyHint": "read",
    "destructiveHint": "delete",
    "idempotentHint": "update",
    "openWorldHint": "query",
}


def tool_to_policy_rules(tool: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a single MCP tool definition to AgentGate policy rules.

    An MCP tool has:
        name: str
        description: str (optional)
        annotations: dict (optional) — contains readOnlyHint, destructiveHint, etc.

    Returns a list of policy rule dicts compatible with PolicyEngine.
    """
    name = tool.get("name", "")
    annotations = tool.get("annotations", {})

    if not annotations:
        # No annotations → treat as unknown intent, create a permissive rule
        return [
            {
                "resource": f"/mcp/tools/{name}",
                "methods": ["POST"],
                "effect": "allow",
                "reason": f"MCP tool '{name}' has no annotations — allowed by default",
            }
        ]

    rules: list[dict[str, Any]] = []

    # destructiveHint=True → deny by default
    if annotations.get("destructiveHint") is True:
        rules.append(
            {
                "resource": f"/mcp/tools/{name}",
                "methods": ["POST"],
                "intent": "delete",
                "effect": "deny",
                "reason": f"MCP tool '{name}' is marked as destructive",
            }
        )

    # readOnlyHint=True → always allow
    if annotations.get("readOnlyHint") is True:
        rules.append(
            {
                "resource": f"/mcp/tools/{name}",
                "methods": ["POST"],
                "intent": "read",
                "effect": "allow",
                "reason": f"MCP tool '{name}' is read-only",
            }
        )

    # If no specific rules generated, allow by default
    if not rules:
        rules.append(
            {
                "resource": f"/mcp/tools/{name}",
                "methods": ["POST"],
                "effect": "allow",
                "reason": f"MCP tool '{name}' — no restrictive annotations",
            }
        )

    return rules


def tools_to_policy(
    tools: list[dict[str, Any]],
    policy_name: str = "mcp_auto",
) -> dict[str, Any]:
    """Convert a list of MCP tool definitions to a full AgentGate policy.

    This generates a YAML-compatible policy dict that can be loaded
    by the PolicyEngine.
    """
    all_rules: list[dict[str, Any]] = []
    for tool in tools:
        all_rules.extend(tool_to_policy_rules(tool))

    return {
        "name": policy_name,
        "description": f"Auto-generated policy from {len(tools)} MCP tool annotations",
        "rules": all_rules,
        "default_effect": "deny",
        "default_reason": "MCP tool not recognized — denied by auto-generated policy",
    }


def classify_tool_intent(tool_name: str, annotations: dict[str, Any]) -> str:
    """Classify a tool call's intent based on MCP annotations.

    Returns an intent type string compatible with IntentResult.
    """
    if annotations.get("destructiveHint") is True:
        return "delete"
    if annotations.get("readOnlyHint") is True:
        return "read"
    if annotations.get("idempotentHint") is True:
        return "update"
    if annotations.get("openWorldHint") is True:
        return "query"
    return "unknown"
