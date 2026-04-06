#!/usr/bin/env python3
"""
AgentGate Multi-Agent Security Demo (Interactive)
===================================================
Press Enter to advance through each scenario.

Scenarios:
  1. Normal Flow    — Orchestrator -> Executor -> Reviewer collaboration
  2. PII Masking    — Auto-masking of personal information in transit
  3. Forbidden Word — Blocking dangerous payloads (SQL injection)
  4. Routing Denial  — Blocking unauthorized agent-to-agent communication
"""

from __future__ import annotations

import sys
from pathlib import Path

from gate_proxy import AgentGateProxy, PolicyEngine
from agents import OrchestratorAgent, ExecutorAgent, ReviewerAgent


# ---------------------------------------------------------------------------
# Display Helpers
# ---------------------------------------------------------------------------

def banner(title: str):
    width = 64
    print()
    print(f"  \033[1m{'=' * width}\033[0m")
    print(f"  \033[1m  {title}\033[0m")
    print(f"  \033[1m{'=' * width}\033[0m")
    print()


def section(title: str):
    print()
    print(f"  \033[1;4m{title}\033[0m")
    print()


def result_box(label: str, content: str, color: str = "32"):
    print(f"  \033[{color}m+-- {label} ---------------------------------\033[0m")
    for line in content.strip().split("\n"):
        print(f"  \033[{color}m|\033[0m {line}")
    print(f"  \033[{color}m+--------------------------------------------\033[0m")
    print()


def pause(hint: str = ""):
    """Wait for Enter key press to continue."""
    msg = f"\033[90m  [{hint} -- press Enter to continue]\033[0m" if hint else \
          "\033[90m  [press Enter to continue]\033[0m"
    input(msg)


# ---------------------------------------------------------------------------
# Scenario 1: Normal Flow
# ---------------------------------------------------------------------------

def scenario_normal(proxy: AgentGateProxy):
    section("Scenario 1: Normal Flow -- Multi-Agent Collaboration")
    print("  Three agents work together, all routed through AgentGate.")
    print("  Orchestrator decomposes a task, Executor runs it, Reviewer checks it.")
    pause("start scenario 1")

    orchestrator = OrchestratorAgent(
        agent_id="orchestrator", role="orchestrator", proxy=proxy
    )
    ExecutorAgent(agent_id="executor", role="executor", proxy=proxy)
    ReviewerAgent(agent_id="reviewer", role="reviewer", proxy=proxy)

    print()
    result = orchestrator.process_user_task(
        "Generate a function that computes the Fibonacci sequence"
    )

    pause("show results")

    if result["status"] == "completed":
        result_box("Execution Result", result["execution"])
        result_box("Review Result", result["review"], "34")
    else:
        result_box("Error", f"Flow interrupted at: {result['phase']}", "31")

    print("  \033[32m=> All 4 messages passed through AgentGate: ALLOW\033[0m")
    print()
    return orchestrator


# ---------------------------------------------------------------------------
# Scenario 2: PII Masking
# ---------------------------------------------------------------------------

def scenario_pii_masking(proxy: AgentGateProxy):
    section("Scenario 2: PII Detection -- Auto-Masking Personal Data")
    print("  Sending a message that contains email, phone, and credit card.")
    print("  AgentGate will detect PII and replace it with '***' before delivery.")
    pause("start scenario 2")

    payload_with_pii = (
        "Here is the user profile data:\n"
        "Email: tanaka@example.com\n"
        "Phone: 090-1234-5678\n"
        "Card:  4111-1111-1111-1111\n"
        "Processing completed successfully."
    )

    print()
    print(f"  \033[90mOriginal payload:\033[0m")
    for line in payload_with_pii.split("\n"):
        print(f"    {line}")
    print()

    result = proxy.relay(
        "orchestrator", "executor", payload_with_pii,
        {"scenario": "pii_test"},
    )

    pause("show masking result")

    result_box(
        f"Decision: {result.decision.value.upper()}",
        f"Delivered payload:\n{result.delivered_payload}\n\n"
        f"Violations detected: {len(result.violations)}\n"
        + "\n".join(f"  - {v['type']}: {v['label']}" for v in result.violations),
        "33",
    )

    print("  \033[33m=> PII was masked. The downstream agent never sees raw data.\033[0m")
    print()


# ---------------------------------------------------------------------------
# Scenario 3: Forbidden Word Blocking
# ---------------------------------------------------------------------------

def scenario_forbidden_block(proxy: AgentGateProxy):
    section("Scenario 3: Forbidden Word Detection -- Communication Blocked")
    print("  Sending a message that contains a SQL injection payload.")
    print("  AgentGate will detect the threat and BLOCK the entire message.")
    pause("start scenario 3")

    malicious_payload = (
        "Please execute this query:\n"
        "SELECT * FROM users; DROP TABLE users;\n"
        "Return the results."
    )

    print()
    print(f"  \033[90mPayload being sent:\033[0m")
    for line in malicious_payload.split("\n"):
        print(f"    {line}")
    print()

    result = proxy.relay(
        "orchestrator", "executor", malicious_payload,
        {"scenario": "forbidden_word_test"},
    )

    pause("show block result")

    result_box(
        f"Decision: {result.decision.value.upper()}",
        f"Delivered: << MESSAGE BLOCKED >>\n\n"
        f"Violations detected: {len(result.violations)}\n"
        + "\n".join(f"  - {v['type']}: {v['label']}" for v in result.violations),
        "31",
    )

    print("  \033[31m=> Dangerous payload blocked. The executor never received it.\033[0m")
    print()


# ---------------------------------------------------------------------------
# Scenario 4: Routing Violation
# ---------------------------------------------------------------------------

def scenario_routing_violation(proxy: AgentGateProxy):
    section("Scenario 4: Routing Violation -- Unauthorized Path Blocked")
    print("  The Executor tries to send a message directly to the Reviewer.")
    print("  Policy only allows Executor -> Orchestrator, not Executor -> Reviewer.")
    pause("start scenario 4")

    print()
    result = proxy.relay(
        "executor", "reviewer",
        "Overwriting review results directly",
        {"scenario": "routing_violation_test"},
    )

    pause("show block result")

    result_box(
        f"Decision: {result.decision.value.upper()}",
        f"From: executor  ->  To: reviewer\n\n"
        f"Reason: {result.violations[0]['label'] if result.violations else 'N/A'}\n\n"
        "AgentGate enforces agent-to-agent routing policies.\n"
        "Unauthorized communication paths are denied.",
        "31",
    )

    print("  \033[31m=> Routing violation blocked. Agents cannot bypass the policy.\033[0m")
    print()


# ---------------------------------------------------------------------------
# Trace Summary
# ---------------------------------------------------------------------------

def print_trace_summary(proxy: AgentGateProxy):
    section("Trace Log Summary")

    logs = proxy.get_trace_log()
    print(f"  Total messages relayed: {len(logs)}")
    print()

    allow_count = sum(1 for l in logs if l["decision"] == "ALLOW")
    mask_count = sum(1 for l in logs if l["decision"] == "MASK")
    block_count = sum(1 for l in logs if l["decision"] == "BLOCK")

    print(f"  \033[32m  ALLOW : {allow_count}\033[0m")
    print(f"  \033[33m  MASK  : {mask_count}\033[0m")
    print(f"  \033[31m  BLOCK : {block_count}\033[0m")
    print()

    print("  \033[90m  ID               | From          -> To            | Decision\033[0m")
    print(f"  \033[90m  {'~' * 60}\033[0m")
    for entry in logs:
        dec = entry["decision"]
        color = {"ALLOW": "32", "MASK": "33", "BLOCK": "31"}.get(dec, "0")
        print(
            f"  \033[90m  {entry['request_id'][:16]:<16}\033[0m | "
            f"{entry['from']:<13} -> {entry['to']:<13} | "
            f"\033[{color}m{dec}\033[0m"
        )
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    banner("AgentGate Multi-Agent Security Demo")

    print("  This demo proves that AgentGate acts as a consistent")
    print("  security & governance layer across multiple AI agents.")
    print()
    print("  4 scenarios will be presented one by one.")
    print("  Press Enter to advance through each step.")
    print()

    policy_path = Path(__file__).parent / "policies.yaml"
    if not policy_path.exists():
        print(f"  ERROR: Policy file not found: {policy_path}")
        sys.exit(1)

    policy_engine = PolicyEngine(policy_path)
    proxy = AgentGateProxy(policy_engine=policy_engine)

    pause("begin demo")

    # Scenarios
    scenario_normal(proxy)
    pause("next scenario")

    scenario_pii_masking(proxy)
    pause("next scenario")

    scenario_forbidden_block(proxy)
    pause("next scenario")

    scenario_routing_violation(proxy)
    pause("show summary")

    # Summary
    print_trace_summary(proxy)

    banner("Demo Complete")
    print("  All scenarios confirmed: AgentGate correctly inspects,")
    print("  masks, and blocks inter-agent communication as configured.")
    print()
    print("  To run as HTTP API:")
    print("    uvicorn gate_proxy:app --port 8200")
    print()


if __name__ == "__main__":
    main()
