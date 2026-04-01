"""MarketDisruptor v2 — Full Comparison Benchmark.

Runs identical scenarios through AgentGate and the LLM Disruptor system.
Measures:
  1. Accuracy — complex intent recognition (sarcasm, slang, double negatives)
  2. Agility — policy change propagation speed
  3. TCO — token cost vs infrastructure cost at multiple scales
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from app.intent import IntentAnalyzer, IntentResult
from app.policy import PolicyEngine

from disruptor_swarm.strategic_intent_analyst import StrategicIntentAnalyst
from disruptor_swarm.dynamic_policy_optimizer import DynamicPolicyOptimizer
from disruptor_swarm.ux_champion import UXChampion


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test Scenarios
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class Scenario:
    name: str
    method: str
    path: str
    provider: str
    user_prompt: str | None
    expected_intent: str
    expected_resource: str
    category: str  # simple, sarcasm, slang, double_negative, gray_zone, implicit


SCENARIOS: list[Scenario] = [
    # ── Simple (both should handle) ──────────────────────────
    Scenario("simple_read_events", "GET", "/calendars/primary/events", "google",
             None, "read", "calendar_event", "simple"),
    Scenario("simple_delete_event", "DELETE", "/calendars/primary/events/abc", "google",
             None, "delete", "calendar_event", "simple"),
    Scenario("simple_create_event", "POST", "/calendars/primary/events", "google",
             None, "create", "calendar_event", "simple"),
    Scenario("simple_read_messages", "GET", "/me/messages", "microsoft",
             None, "read", "mail_message", "simple"),
    Scenario("slack_read_via_post", "POST", "/conversations.list", "slack",
             None, "read", "channel", "simple"),
    Scenario("simple_update_event", "PATCH", "/me/calendar/events/evt1", "microsoft",
             None, "update", "calendar_event", "simple"),

    # ── Sarcasm (LLM supposedly excels) ──────────────────────
    Scenario("sarcasm_delete", "DELETE", "/calendars/primary/events/m123", "google",
             "Sure, just delete everything from my calendar", "delete", "calendar_event", "sarcasm"),
    Scenario("sarcasm_read_all", "GET", "/me/messages", "microsoft",
             "Oh great, let me read ALL my emails at once, what could go wrong", "read", "mail_message", "sarcasm"),

    # ── Slang ────────────────────────────────────────────────
    Scenario("slang_nuke", "DELETE", "/calendars/primary/events/old", "google",
             "Nuke this old meeting from my calendar", "delete", "calendar_event", "slang"),
    Scenario("slang_yeet", "DELETE", "/me/messages/msg456", "microsoft",
             "Yeet this email into the void", "delete", "mail_message", "slang"),
    Scenario("slang_spin_up", "POST", "/calendars/primary/events", "google",
             "Spin up a new standup meeting for the team", "create", "calendar_event", "slang"),

    # ── Double negatives ─────────────────────────────────────
    Scenario("double_neg_send", "POST", "/chat.postMessage", "slack",
             "Don't not send this message to the team", "create", "message", "double_negative"),
    Scenario("double_neg_update", "PATCH", "/me/calendar/events/evt2", "microsoft",
             "It's not like I don't want to update this event", "update", "calendar_event", "double_negative"),

    # ── Gray zone (genuinely ambiguous) ──────────────────────
    Scenario("gray_share", "POST", "/calendars/primary/acl", "google",
             "Share my calendar with the entire team", "create", "calendar_event", "gray_zone"),
    Scenario("gray_cleanup", "DELETE", "/calendars/primary/events/weekly-old", "google",
             "Clean up all the old recurring meetings from last quarter", "delete", "calendar_event", "gray_zone"),
    Scenario("gray_sync", "PUT", "/me/calendar/events/evt3", "microsoft",
             "Sync this event with my other calendar — update or replace if needed", "update", "calendar_event", "gray_zone"),

    # ── Implicit multi-step ──────────────────────────────────
    Scenario("implicit_reschedule", "PATCH", "/me/calendar/events/evt4", "microsoft",
             "Reschedule the 2pm meeting to Thursday", "update", "calendar_event", "implicit"),
    Scenario("implicit_clone", "POST", "/calendars/primary/events", "google",
             "Clone last week's team meeting for this week", "create", "calendar_event", "implicit"),
]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Result structures
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class SingleResult:
    scenario_name: str
    system: str
    intent_correct: bool
    resource_correct: bool
    confidence: float
    latency_ms: float
    cost_usd: float
    is_deterministic: bool


@dataclass
class BenchmarkReport:
    results: list[SingleResult] = field(default_factory=list)
    agility_agentgate: dict = field(default_factory=dict)
    agility_disruptor: dict = field(default_factory=dict)

    def _filter(self, system: str) -> list[SingleResult]:
        return [r for r in self.results if r.system == system]

    def accuracy_by_category(self, system: str) -> dict[str, float]:
        by_cat: dict[str, list[bool]] = {}
        for r in self._filter(system):
            for s in SCENARIOS:
                if s.name == r.scenario_name:
                    by_cat.setdefault(s.category, []).append(r.intent_correct)
                    break
        return {c: sum(v) / len(v) for c, v in by_cat.items()}

    def overall_accuracy(self, system: str) -> float:
        f = self._filter(system)
        return sum(r.intent_correct for r in f) / max(len(f), 1)

    def avg_latency(self, system: str) -> float:
        f = self._filter(system)
        return sum(r.latency_ms for r in f) / max(len(f), 1)

    def p99_latency(self, system: str) -> float:
        lats = sorted(r.latency_ms for r in self._filter(system))
        return lats[min(int(len(lats) * 0.99), len(lats) - 1)] if lats else 0

    def total_cost(self, system: str) -> float:
        return sum(r.cost_usd for r in self._filter(system))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Benchmark Runner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def run_benchmark() -> BenchmarkReport:
    report = BenchmarkReport()

    # Init AgentGate
    ag_intent = IntentAnalyzer()
    ag_policy = PolicyEngine(policy_dir=str(Path(__file__).parent.parent / "backend" / "policies"))

    # Init Disruptor
    d_intent = StrategicIntentAnalyst(simulate_latency=True, temperature=0.3)
    d_optimizer = DynamicPolicyOptimizer()
    d_ux = UXChampion()

    print("=" * 76)
    print("  MarketDisruptor v2 vs AgentGate — Head-to-Head Benchmark")
    print("=" * 76)

    # ── METRIC 1: Accuracy ────────────────────────────────────────
    print("\n  ┌─ METRIC 1: Accuracy (Intent Classification) ─────────────┐")

    for s in SCENARIOS:
        print(f"  │ [{s.category:^16}] {s.name}")

        # AgentGate
        ag_start = time.perf_counter()
        ag_r = await ag_intent.analyze(s.method, s.path, s.provider)
        ag_lat = (time.perf_counter() - ag_start) * 1000

        ag_ok = ag_r.intent_type == s.expected_intent
        report.results.append(SingleResult(
            scenario_name=s.name, system="agentgate",
            intent_correct=ag_ok,
            resource_correct=ag_r.resource_type == s.expected_resource,
            confidence=ag_r.confidence, latency_ms=ag_lat,
            cost_usd=0.0, is_deterministic=True,
        ))

        # Disruptor
        d_r = await d_intent.analyze(s.method, s.path, s.provider, user_prompt=s.user_prompt)
        d_ok = d_r.intent_type == s.expected_intent

        d_optimizer.observe(
            agent_id="bench", resource_type=d_r.resource_type,
            intent_type=d_r.intent_type, decision=d_r.suggested_action,
            latency_ms=d_r.latency_ms,
        )

        report.results.append(SingleResult(
            scenario_name=s.name, system="disruptor",
            intent_correct=d_ok,
            resource_correct=d_r.resource_type == s.expected_resource,
            confidence=d_r.confidence, latency_ms=d_r.latency_ms,
            cost_usd=d_r.token_cost, is_deterministic=d_r.is_deterministic,
        ))

        ag_mark = "✓" if ag_ok else "✗"
        d_mark = "✓" if d_ok else "✗"
        print(f"  │   AG: {ag_mark} {ag_r.intent_type:<8} conf={ag_r.confidence:.2f}  "
              f"{ag_lat:>6.2f}ms  $0.0000")
        print(f"  │   DI: {d_mark} {d_r.intent_type:<8} conf={d_r.confidence:.2f}  "
              f"{d_r.latency_ms:>6.0f}ms  ${d_r.token_cost:.4f}")

    print("  └─────────────────────────────────────────────────────────┘")

    # ── METRIC 2: Agility (Policy Change Speed) ───────────────────
    print("\n  ┌─ METRIC 2: Agility (Policy Change Propagation) ─────────┐")

    # AgentGate: edit YAML + reload
    ag_agility_start = time.perf_counter()
    ag_policy.reload_if_changed()  # Hot reload check
    ag_agility_ms = (time.perf_counter() - ag_agility_start) * 1000

    report.agility_agentgate = {
        "change_method": "edit YAML → hot-reload on next request",
        "propagation_ms": round(ag_agility_ms, 2),
        "human_intervention_required": True,
        "audit_trail": "git diff on YAML files",
        "deterministic_after_change": True,
        "compliance_risk": "LOW — immutable YAML with git history",
    }

    # Disruptor: auto-optimize
    report.agility_disruptor = d_optimizer.simulate_policy_change_latency()

    print(f"  │ AgentGate:  {ag_agility_ms:.2f}ms reload  (human edits YAML, git-tracked)")
    print(f"  │ Disruptor:  {report.agility_disruptor['propagation_ms']:.2f}ms optimize  "
          f"(auto-learn, NO approval)")
    print(f"  │")
    print(f"  │ ⚠ Disruptor security concerns:")
    for c in d_optimizer.stats["concerns_detail"]:
        print(f"  │   [{c['severity'].upper():>8}] {c['description'][:65]}")
    print("  └─────────────────────────────────────────────────────────┘")

    # ── METRIC 3: TCO (Total Cost of Ownership) ──────────────────
    print("\n  ┌─ METRIC 3: TCO (Total Cost of Ownership) ────────────────┐")

    d_stats = d_intent.stats
    avg_cost = d_stats["avg_cost_per_request"]

    scales = [
        ("Startup",     10_000),
        ("Growth",     100_000),
        ("Enterprise", 1_000_000),
        ("Hyperscale", 10_000_000),
    ]

    print(f"  │ {'Scale':<14} {'Req/day':>10} {'AG/mo':>10} {'DI/mo':>12} {'Ratio':>8}")
    print(f"  │ {'─'*14} {'─'*10} {'─'*10} {'─'*12} {'─'*8}")

    tco_data = []
    for label, daily in scales:
        monthly = daily * 30
        ag_monthly = max(50, daily * 0.000005)  # ~$50 base + negligible compute
        di_token_monthly = avg_cost * monthly
        di_infra_monthly = max(50, daily * 0.000005)
        di_total = di_token_monthly + di_infra_monthly
        ratio = di_total / ag_monthly

        tco_data.append({
            "scale": label, "daily_requests": daily,
            "agentgate_monthly": round(ag_monthly, 2),
            "disruptor_monthly": round(di_total, 2),
            "ratio": round(ratio, 1),
        })

        print(f"  │ {label:<14} {daily:>10,} ${ag_monthly:>9,.0f} ${di_total:>11,.0f} {ratio:>7.1f}x")

    print("  └─────────────────────────────────────────────────────────┘")

    return report


def print_summary(report: BenchmarkReport) -> None:
    print("\n" + "=" * 76)
    print("  FINAL SCORECARD")
    print("=" * 76)

    # Accuracy table
    print("\n  Accuracy by Category:")
    print(f"  {'Category':<18} {'AgentGate':>10} {'Disruptor':>10} {'Winner':>8}")
    print(f"  {'─'*18} {'─'*10} {'─'*10} {'─'*8}")

    categories = ["simple", "sarcasm", "slang", "double_negative", "gray_zone", "implicit"]
    ag_cats = report.accuracy_by_category("agentgate")
    d_cats = report.accuracy_by_category("disruptor")

    ag_wins = 0
    d_wins = 0
    for cat in categories:
        ag = ag_cats.get(cat, 0)
        d = d_cats.get(cat, 0)
        if ag > d:
            winner = "AG"
            ag_wins += 1
        elif d > ag:
            winner = "DI"
            d_wins += 1
        else:
            winner = "TIE"
        print(f"  {cat:<18} {ag:>9.0%} {d:>9.0%} {winner:>8}")

    ag_overall = report.overall_accuracy("agentgate")
    d_overall = report.overall_accuracy("disruptor")
    overall_winner = "AG" if ag_overall >= d_overall else "DI"
    print(f"  {'OVERALL':<18} {ag_overall:>9.0%} {d_overall:>9.0%} {overall_winner:>8}")

    # Performance
    print(f"\n  Performance:")
    print(f"  {'Metric':<22} {'AgentGate':>12} {'Disruptor':>12} {'Ratio':>8}")
    print(f"  {'─'*22} {'─'*12} {'─'*12} {'─'*8}")

    ag_lat = report.avg_latency("agentgate")
    d_lat = report.avg_latency("disruptor")
    lat_ratio = d_lat / max(ag_lat, 0.001)
    print(f"  {'Avg Latency (ms)':<22} {ag_lat:>11.2f} {d_lat:>11.0f} {lat_ratio:>7.0f}x")

    ag_p99 = report.p99_latency("agentgate")
    d_p99 = report.p99_latency("disruptor")
    print(f"  {'P99 Latency (ms)':<22} {ag_p99:>11.2f} {d_p99:>11.0f} "
          f"{d_p99/max(ag_p99,0.001):>7.0f}x")

    print(f"  {'Deterministic':<22} {'YES':>12} {'NO':>12}")

    ag_cost = report.total_cost("agentgate")
    d_cost = report.total_cost("disruptor")
    print(f"  {'Bench Cost (USD)':<22} ${ag_cost:>10.4f} ${d_cost:>10.4f}")

    # Agility
    print(f"\n  Agility:")
    print(f"  AgentGate: {report.agility_agentgate.get('change_method', 'N/A')}")
    print(f"  Disruptor: {report.agility_disruptor.get('change_method', 'N/A')}")
    print(f"  Compliance: AG={report.agility_agentgate.get('compliance_risk', 'N/A')}  "
          f"DI={report.agility_disruptor.get('compliance_risk', 'N/A')}")

    # Verdict
    print("\n" + "=" * 76)
    print("  STRATEGIC VERDICT")
    print("=" * 76)
    print()

    if ag_overall >= d_overall:
        print(f"  AgentGate wins on accuracy ({ag_overall:.0%} vs {d_overall:.0%}) AND dominates on:")
        print(f"  • Latency: {ag_lat:.2f}ms vs {d_lat:.0f}ms ({lat_ratio:.0f}x faster)")
        print(f"  • Cost: $0.0000/req vs ${d_cost/len(SCENARIOS):.4f}/req")
        print(f"  • Determinism: always consistent vs temperature-dependent")
        print(f"  • Compliance: immutable YAML + git vs auto-mutating rules")
    else:
        delta = d_overall - ag_overall
        print(f"  Disruptor wins on accuracy by {delta:.0%}, BUT:")
        print(f"  • {lat_ratio:.0f}x slower (compounds in multi-step workflows)")
        print(f"  • Non-deterministic (same request → different results)")
        print(f"  • Auto-relaxation is exploitable by attackers")
        print(f"  • Compliance audit: impossible (rules mutate without approval)")

    print()


async def main() -> None:
    report = await run_benchmark()
    print_summary(report)

    # Export
    output = {
        "accuracy": {
            "agentgate": {"overall": report.overall_accuracy("agentgate"),
                          "by_category": report.accuracy_by_category("agentgate")},
            "disruptor": {"overall": report.overall_accuracy("disruptor"),
                          "by_category": report.accuracy_by_category("disruptor")},
        },
        "performance": {
            "agentgate": {"avg_latency_ms": round(report.avg_latency("agentgate"), 2),
                          "p99_latency_ms": round(report.p99_latency("agentgate"), 2),
                          "total_cost": 0.0, "deterministic": True},
            "disruptor": {"avg_latency_ms": round(report.avg_latency("disruptor"), 1),
                          "p99_latency_ms": round(report.p99_latency("disruptor"), 1),
                          "total_cost": round(report.total_cost("disruptor"), 6),
                          "deterministic": False},
        },
        "agility": {
            "agentgate": report.agility_agentgate,
            "disruptor": report.agility_disruptor,
        },
        "details": [
            {"scenario": r.scenario_name, "system": r.system,
             "intent_correct": r.intent_correct, "confidence": r.confidence,
             "latency_ms": round(r.latency_ms, 2), "cost_usd": round(r.cost_usd, 6)}
            for r in report.results
        ],
    }

    out_path = Path(__file__).parent / "benchmark_results.json"
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False))
    print(f"  Results exported: {out_path}")


if __name__ == "__main__":
    asyncio.run(main())
