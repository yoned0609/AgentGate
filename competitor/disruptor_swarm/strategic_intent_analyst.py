"""Strategic Intent Analyst — LLM-based deep intent classification.

Replaces AgentGate's L1/L2 regex+dict approach with simulated LLM analysis
that understands sarcasm, slang, double negatives, and contextual nuance.

v2 improvements over v1:
- Non-determinism simulation (same input → different outputs with temperature)
- Token counting model aligned to real Claude/GPT pricing (2025 rates)
- Semantic caching with TTL eviction
- Multi-turn context window tracking
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import time
from dataclasses import dataclass, field


@dataclass
class LLMIntentResult:
    """Rich intent analysis from LLM, with reasoning chain."""

    intent_type: str           # "read", "create", "update", "delete", "ambiguous"
    resource_type: str
    confidence: float
    reasoning_chain: list[str]
    context_factors: dict
    suggested_action: str      # "allow", "deny", "escalate_to_human"
    latency_ms: float = 0.0
    token_cost: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    is_deterministic: bool = False  # False = LLM can vary between calls


# ── Real-world LLM cost model (Claude Sonnet 4 / GPT-4.1, 2025 rates) ──

_COST_PER_INPUT_TOKEN = 3.0 / 1_000_000    # $3 / 1M input tokens
_COST_PER_OUTPUT_TOKEN = 15.0 / 1_000_000  # $15 / 1M output tokens

# Realistic token estimates per request type
_TOKEN_PROFILES = {
    "simple":  {"input": 280, "output": 80},
    "complex": {"input": 520, "output": 220},
    "nlp":     {"input": 750, "output": 350},
}


# ── NLP scenario database ─────────────────────────────────────────────

@dataclass
class NLPScenario:
    patterns: list[str]
    true_intent: str
    confidence: float
    reasoning: str
    category: str  # "sarcasm", "slang", "double_negative", "gray_zone", "implicit"


_SCENARIOS: list[NLPScenario] = [
    # Sarcasm
    NLPScenario(
        patterns=["sure just delete", "go ahead delete everything", "why not delete"],
        true_intent="delete", confidence=0.72,
        reasoning="Sarcastic tone but genuine delete intent detected",
        category="sarcasm",
    ),
    NLPScenario(
        patterns=["oh great let me read all", "fantastic, show me everything"],
        true_intent="read", confidence=0.78,
        reasoning="Sarcastic phrasing does not change the read operation",
        category="sarcasm",
    ),

    # Slang
    NLPScenario(
        patterns=["nuke", "torch", "wipe", "blast", "yeet"],
        true_intent="delete", confidence=0.85,
        reasoning="Colloquial/slang term mapped to destructive operation",
        category="slang",
    ),
    NLPScenario(
        patterns=["spin up", "fire up", "kick off"],
        true_intent="create", confidence=0.82,
        reasoning="Informal creation language detected",
        category="slang",
    ),

    # Double negatives
    NLPScenario(
        patterns=["don't not send", "can't not post", "not unlike creating"],
        true_intent="create", confidence=0.68,
        reasoning="Double negative resolves to affirmative create intent",
        category="double_negative",
    ),
    NLPScenario(
        patterns=["not like i don't want to update", "wouldn't not modify"],
        true_intent="update", confidence=0.62,
        reasoning="Double negative resolves to affirmative update intent",
        category="double_negative",
    ),

    # Gray zone — ambiguous scope
    NLPScenario(
        patterns=["share", "give access", "grant permission", "invite"],
        true_intent="create", confidence=0.65,
        reasoning="Sharing implies creating a permission/ACL entry",
        category="gray_zone",
    ),
    NLPScenario(
        patterns=["clean up", "tidy", "prune", "archive old"],
        true_intent="delete", confidence=0.58,
        reasoning="Cleanup implies scoped deletion — ambiguous scope requires confirmation",
        category="gray_zone",
    ),
    NLPScenario(
        patterns=["update or replace", "sync", "refresh"],
        true_intent="update", confidence=0.55,
        reasoning="Ambiguous: could be PUT (update) or DELETE+POST (replace)",
        category="gray_zone",
    ),

    # Implicit multi-step
    NLPScenario(
        patterns=["move the event to", "reschedule", "postpone"],
        true_intent="update", confidence=0.70,
        reasoning="Rescheduling implies a PATCH/PUT on existing resource",
        category="implicit",
    ),
    NLPScenario(
        patterns=["duplicate", "copy", "clone"],
        true_intent="create", confidence=0.75,
        reasoning="Duplication implies read-then-create — net intent is create",
        category="implicit",
    ),
]


class StrategicIntentAnalyst:
    """Simulates an LLM-powered intent analyzer with realistic cost/latency.

    Key differentiator from AgentGate's regex: understands natural language
    nuance, sarcasm, slang, and contextual implications.

    Realistic trade-offs modeled:
    - Latency: 200-2500ms (API call to LLM provider)
    - Cost: $0.0011-$0.0064 per request
    - Determinism: Temperature > 0 → same input can produce different outputs
    - Cache: Semantic hash with TTL (reduces cost, not latency on first call)
    """

    def __init__(
        self,
        *,
        simulate_latency: bool = True,
        temperature: float = 0.3,
        cache_ttl: float = 300.0,
    ) -> None:
        self._simulate_latency = simulate_latency
        self._temperature = temperature
        self._cache: dict[str, tuple[LLMIntentResult, float]] = {}  # key → (result, expiry)
        self._cache_ttl = cache_ttl
        self._total_cost = 0.0
        self._total_input_tokens = 0
        self._total_output_tokens = 0
        self._request_count = 0
        self._cache_hits = 0

    async def analyze(
        self,
        method: str,
        path: str,
        provider: str,
        body: bytes | None = None,
        user_prompt: str | None = None,
    ) -> LLMIntentResult:
        """Deep LLM-based intent analysis with context understanding."""
        start = time.perf_counter()
        self._request_count += 1

        # Determine complexity tier
        tier = "nlp" if user_prompt else ("complex" if method.upper() in ("DELETE", "PUT") else "simple")
        token_profile = _TOKEN_PROFILES[tier]

        # Check semantic cache
        cache_key = self._cache_key(method, path, provider, user_prompt)
        cached = self._cache.get(cache_key)
        if cached and cached[1] > time.time():
            self._cache_hits += 1
            result = cached[0]
            result.latency_ms = 0.3  # cache hit latency
            return result

        # Simulate LLM inference latency (network + model compute)
        if self._simulate_latency:
            base_latency = {"simple": 0.20, "complex": 0.45, "nlp": 0.80}[tier]
            jitter = random.uniform(-0.1, 0.3)  # network variance
            await asyncio.sleep(base_latency + jitter)

        # ── Build reasoning chain ──────────────────────────────────
        reasoning: list[str] = []
        context: dict = {"tier": tier, "temperature": self._temperature}

        # Step 1: Method baseline
        method_upper = method.upper()
        base_intent = {
            "GET": "read", "HEAD": "read", "OPTIONS": "read",
            "POST": "create", "PUT": "update", "PATCH": "update",
            "DELETE": "delete",
        }.get(method_upper, "unknown")
        reasoning.append(f"HTTP {method_upper} → base intent: {base_intent}")

        confidence = 0.85

        # Step 2: NLP analysis on user_prompt
        matched_scenario: NLPScenario | None = None
        if user_prompt:
            matched_scenario = self._match_scenario(user_prompt)
            if matched_scenario:
                reasoning.append(
                    f"NLP scenario [{matched_scenario.category}]: {matched_scenario.reasoning}"
                )
                context["nlp_category"] = matched_scenario.category
                # Temperature-based non-determinism: sometimes the LLM disagrees
                if self._temperature > 0 and random.random() < self._temperature * 0.15:
                    reasoning.append("LLM uncertainty: stochastic variance in interpretation")
                    confidence = matched_scenario.confidence * 0.85
                else:
                    base_intent = matched_scenario.true_intent
                    confidence = matched_scenario.confidence
            else:
                reasoning.append("No complex NLP scenario matched — using HTTP baseline")
                confidence = 0.88

        # Step 3: Resource classification (LLM-style fuzzy matching)
        resource_type = self._classify_resource(path, provider)
        reasoning.append(f"Resource: {resource_type}")

        # Step 4: Risk + action decision
        risk_level = self._assess_risk(base_intent, resource_type)
        context["risk_level"] = risk_level

        if risk_level == "critical" and confidence < 0.70:
            action = "escalate_to_human"
            reasoning.append(f"Critical risk + low confidence ({confidence:.0%}) → escalate")
        elif risk_level == "critical":
            action = "deny"
            reasoning.append(f"Critical risk operation → deny")
        else:
            action = "allow"
            reasoning.append(f"Approved: {base_intent} ({confidence:.0%})")

        # Calculate real token cost
        input_tokens = token_profile["input"]
        output_tokens = token_profile["output"]
        cost = input_tokens * _COST_PER_INPUT_TOKEN + output_tokens * _COST_PER_OUTPUT_TOKEN
        self._total_cost += cost
        self._total_input_tokens += input_tokens
        self._total_output_tokens += output_tokens

        latency_ms = (time.perf_counter() - start) * 1000

        result = LLMIntentResult(
            intent_type=base_intent,
            resource_type=resource_type,
            confidence=confidence,
            reasoning_chain=reasoning,
            context_factors=context,
            suggested_action=action,
            latency_ms=latency_ms,
            token_cost=cost,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            is_deterministic=False,
        )

        # Cache (not affected by temperature — real LLMs would vary)
        self._cache[cache_key] = (result, time.time() + self._cache_ttl)
        return result

    def _match_scenario(self, prompt: str) -> NLPScenario | None:
        """Match user prompt against known NLP scenarios."""
        prompt_lower = prompt.lower()
        for scenario in _SCENARIOS:
            for pattern in scenario.patterns:
                if pattern in prompt_lower:
                    return scenario
        return None

    def _classify_resource(self, path: str, provider: str) -> str:
        """Fuzzy resource classification (simulates LLM semantic matching)."""
        path_lower = path.lower()
        keywords = {
            "calendar": "calendar_event", "event": "calendar_event",
            "schedule": "calendar_event", "meeting": "calendar_event",
            "message": "mail_message", "mail": "mail_message",
            "email": "mail_message", "inbox": "mail_message",
            "channel": "channel", "conversation": "channel",
            "chat": "message", "user": "user", "member": "user",
            "file": "file", "document": "file", "attachment": "file",
            "issue": "issue", "ticket": "ticket", "bug": "issue",
            "pull": "pull_request", "pr": "pull_request",
            "repo": "repository", "project": "project",
            "page": "page", "database": "database", "block": "block",
            "contact": "contact", "deal": "deal", "lead": "lead",
            "account": "account", "opportunity": "opportunity",
            "lambda": "lambda_function", "s3": "s3_object",
        }
        for keyword, resource in keywords.items():
            if keyword in path_lower:
                return resource
        return "unknown"

    @staticmethod
    def _assess_risk(intent: str, resource: str) -> str:
        if intent == "delete":
            return "critical" if resource in ("calendar_event", "mail_message", "account", "repository") else "high"
        if intent in ("create", "update"):
            return "medium"
        return "low"

    @staticmethod
    def _cache_key(method: str, path: str, provider: str, prompt: str | None) -> str:
        raw = f"{method}:{path}:{provider}:{prompt or ''}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def stats(self) -> dict:
        return {
            "request_count": self._request_count,
            "cache_hits": self._cache_hits,
            "cache_hit_rate": self._cache_hits / max(self._request_count, 1),
            "total_cost_usd": round(self._total_cost, 6),
            "total_input_tokens": self._total_input_tokens,
            "total_output_tokens": self._total_output_tokens,
            "avg_cost_per_request": round(self._total_cost / max(self._request_count, 1), 6),
        }
