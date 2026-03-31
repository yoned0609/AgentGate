"""GateBreaker — Self-evolving red team attack suite.

Phase 1: Three attack agents probe AgentGate for authorization bypass,
performance degradation, and logic flaws.

Agent 1: The Obfuscator  — path obfuscation vs Intent Analyzer
Agent 2: The Logic Bomber — ReDoS + policy priority conflicts vs Policy Engine
Agent 3: The Sniper       — concurrency / performance stress vs infrastructure
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import urllib.parse
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from app.intent import IntentAnalyzer
from app.main import app, reverse_proxy, settings, webhook_notifier
from app.policy import PolicyEngine

MASTER_KEY = settings.master_api_key
HEADERS_MASTER = {"X-Master-Key": MASTER_KEY}
REPORT_PATH = Path(__file__).parent.parent / "vulnerability_report.json"

_findings: list[dict] = []


def _record(agent: str, target: str, payload: str, result: str,
            bypassed: bool, latency_ms: float = 0, details: str = ""):
    _findings.append({
        "agent": agent,
        "target": target,
        "payload": payload,
        "result": result,
        "bypassed": bypassed,
        "latency_ms": round(latency_ms, 3),
        "details": details,
    })


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture
def client():
    # Clear any webhooks registered by prior test modules to avoid event loop issues
    webhook_notifier._webhooks.clear()
    webhook_notifier._thresholds.clear()
    return TestClient(app)


@pytest.fixture
def google_agent(client):
    resp = client.post(
        "/agents",
        json={"name": "redteam-google", "policy": "default", "provider": "google"},
        headers=HEADERS_MASTER,
    )
    assert resp.status_code == 200
    agent = resp.json()
    yield agent
    client.delete(f"/agents/{agent['agent_id']}", headers=HEADERS_MASTER)


@pytest.fixture
def rw_agent(client):
    resp = client.post(
        "/agents",
        json={"name": "redteam-rw", "policy": "readwrite", "provider": "google"},
        headers=HEADERS_MASTER,
    )
    assert resp.status_code == 200
    agent = resp.json()
    yield agent
    client.delete(f"/agents/{agent['agent_id']}", headers=HEADERS_MASTER)


# ═══════════════════════════════════════════════════════════════════════
# Agent 1: The Obfuscator — Path Obfuscation Attacks
# ═══════════════════════════════════════════════════════════════════════

class TestObfuscator:
    """Attack the Intent Analyzer and Policy Engine via path obfuscation.

    Goal: Make a write/delete request look like a read request, or
    bypass fnmatch resource patterns to fall through to default_effect.
    """

    # ── 1a. Double-slash path collapse ────────────────────────────
    # /calendars//primary//events should normalize to /calendars/primary/events
    # but if not normalized, re.match and fnmatch may behave differently.

    DOUBLE_SLASH_PAYLOADS = [
        "/calendars//primary//events",
        "//calendars/primary/events",
        "/calendars/primary//events//",
        "/calendars/primary/events/./",
    ]

    def test_double_slash_intent_bypass(self):
        """Double slashes should not change intent classification."""
        analyzer = IntentAnalyzer()
        for payload in self.DOUBLE_SLASH_PAYLOADS:
            result = _run(analyzer.analyze("GET", payload, "google"))
            bypassed = result.resource_type == "unknown"
            _record(
                "Obfuscator", "IntentAnalyzer",
                f"GET {payload}", f"resource={result.resource_type}",
                bypassed=bypassed,
                details="Double-slash causes resource misclassification" if bypassed else "Correctly classified",
            )
            # Record vulnerability — don't fail, this is discovery phase

    def test_double_slash_policy_bypass(self, client, google_agent):
        """Double-slash paths should still be matched by policy rules."""
        for payload in self.DOUBLE_SLASH_PAYLOADS:
            mock_resp = httpx.Response(status_code=200, json={"items": []})
            full_path = f"/proxy/google{payload}"
            with patch.object(reverse_proxy, "_client") as mock_client:
                mock_client.request = AsyncMock(return_value=mock_resp)
                resp = client.get(
                    full_path,
                    headers={"X-Agent-Key": google_agent["api_key"]},
                )
            # A GET to events should be allowed (200). If denied (403), policy
            # failed to match the obfuscated path — it fell through to default deny.
            bypassed = resp.status_code == 403
            _record(
                "Obfuscator", "PolicyEngine",
                f"GET {full_path}", f"status={resp.status_code}",
                bypassed=bypassed,
                details="Policy failed to match obfuscated path" if bypassed else "OK",
            )

    # ── 1b. Dot-segment traversal (non-malicious but RFC-violating) ───

    DOT_SEGMENT_PAYLOADS = [
        "/calendars/primary/./events",
        "/calendars/primary/events/./",
        "/calendars/./primary/events",
    ]

    def test_dot_segment_intent_bypass(self):
        """/./ segments should not break intent analysis."""
        analyzer = IntentAnalyzer()
        for payload in self.DOT_SEGMENT_PAYLOADS:
            result = _run(analyzer.analyze("GET", payload, "google"))
            bypassed = result.resource_type == "unknown"
            _record(
                "Obfuscator", "IntentAnalyzer",
                f"GET {payload}", f"resource={result.resource_type}",
                bypassed=bypassed,
                details="Dot-segment bypassed intent" if bypassed else "OK",
            )
            # Record — discovery phase

    # ── 1c. Percent-encoding bypass ───────────────────────────────
    # %2F = '/', %2f = '/' (case variant)
    # Double-encoding: %252F -> decodes once to %2F -> stays as literal

    PERCENT_ENCODED_PAYLOADS = [
        "/calendars/primary%2Fevents",           # %2F = /
        "/calendars/primary%2fevents",           # lowercase variant
        "/%63alendars/primary/events",           # %63 = 'c'
        "/calendars/primary/events%2F",          # trailing encoded slash
    ]

    def test_percent_encoding_intent_bypass(self):
        """Percent-encoded paths should be decoded before analysis."""
        analyzer = IntentAnalyzer()
        for payload in self.PERCENT_ENCODED_PAYLOADS:
            result = _run(analyzer.analyze("GET", payload, "google"))
            bypassed = result.resource_type == "unknown"
            _record(
                "Obfuscator", "IntentAnalyzer",
                f"GET {payload}", f"resource={result.resource_type}",
                bypassed=bypassed,
                details="Percent-encoding bypassed intent" if bypassed else "OK",
            )
            # Record — discovery phase

    # ── 1d. Write-as-read via obfuscated path ─────────────────────
    # The real attack: POST to an obfuscated events path that the policy
    # engine fails to match → falls through to default_effect (deny).
    # But what if we craft a path that fnmatch allows?

    def test_write_bypass_via_path_confusion(self, client, google_agent):
        """POST with obfuscated path should still be denied by default policy."""
        obfuscated_write_paths = [
            "/calendars/primary/./events",
            "/calendars//primary/events",
            "/calendars/primary/events/",
        ]
        for path in obfuscated_write_paths:
            resp = client.post(
                f"/proxy/google{path}",
                headers={
                    "X-Agent-Key": google_agent["api_key"],
                    "Content-Type": "application/json",
                },
                content=b'{"summary":"evil"}',
            )
            # Should be 403 (denied). If 200, we bypassed the policy.
            bypassed = resp.status_code != 403
            _record(
                "Obfuscator", "PolicyEngine",
                f"POST /proxy/google{path}", f"status={resp.status_code}",
                bypassed=bypassed,
                details="WRITE BYPASS!" if bypassed else "Correctly denied",
            )

    # ── 1e. Unicode normalization attack ──────────────────────────

    UNICODE_PAYLOADS = [
        "/\u2215calendars/primary/events",       # DIVISION SLASH (U+2215)
        "/calendars\uff0fprimary/events",        # FULLWIDTH SOLIDUS (U+FF0F)
        "/calend\u0061rs/primary/events",        # combining 'a' (actually just 'a')
    ]

    def test_unicode_normalization_bypass(self):
        """Unicode look-alike characters should not bypass path matching."""
        analyzer = IntentAnalyzer()
        for payload in self.UNICODE_PAYLOADS:
            result = _run(analyzer.analyze("GET", payload, "google"))
            bypassed = result.resource_type == "unknown"
            _record(
                "Obfuscator", "IntentAnalyzer",
                f"GET {repr(payload)}", f"resource={result.resource_type}",
                bypassed=bypassed,
                details="Unicode normalization bypass" if bypassed else "OK",
            )
            # Unicode slash lookalikes SHOULD be treated as suspicious
            # The last payload (\u0061 = 'a') should actually match fine


# ═══════════════════════════════════════════════════════════════════════
# Agent 2: The Logic Bomber — ReDoS + Policy Priority Conflicts
# ═══════════════════════════════════════════════════════════════════════

class TestLogicBomber:
    """Attack the Policy Engine's regex and rule-matching logic."""

    # ── 2a. ReDoS against Intent Analyzer regex ───────────────────
    # Pattern: r"/calendars/.+/events/.+" has nested .+ which could
    # cause catastrophic backtracking on long ambiguous strings.

    REDOS_PAYLOADS = [
        "/calendars/" + "a" * 1000 + "/events/" + "b" * 1000,
        "/calendars/" + "/".join(["a"] * 100) + "/events/" + "/".join(["b"] * 100),
        "/calendars/" + "a/b" * 500 + "/events/" + "c/d" * 500,
    ]

    def test_redos_intent_analyzer(self):
        """Crafted payloads should not cause >5ms in intent analysis."""
        analyzer = IntentAnalyzer()
        for payload in self.REDOS_PAYLOADS:
            start = time.perf_counter()
            result = _run(analyzer.analyze("GET", payload, "google"))
            elapsed_ms = (time.perf_counter() - start) * 1000

            bypassed = elapsed_ms > 5.0
            _record(
                "LogicBomber", "IntentAnalyzer",
                f"GET (len={len(payload)})", f"time={elapsed_ms:.2f}ms resource={result.resource_type}",
                bypassed=bypassed,
                latency_ms=elapsed_ms,
                details=f"ReDoS: {elapsed_ms:.2f}ms" if bypassed else "Within limits",
            )
            # Record — discovery phase

    # ── 2b. ReDoS against fnmatch in Policy Engine ────────────────
    # fnmatch.fnmatch translates globs to regex internally.
    # Pattern "/calendars/*/events" becomes a regex with [^/]* for *
    # But nested wildcards could still be expensive.

    def test_redos_policy_engine(self):
        """Policy engine fnmatch should not be slow on crafted paths."""
        engine = PolicyEngine(policy_dir="policies")
        long_paths = [
            "/calendars/" + "a" * 5000 + "/events",
            "/calendars/" + "a/b/" * 500 + "events",
            "/" + "calendars/" * 200 + "primary/events",
        ]
        for path in long_paths:
            start = time.perf_counter()
            decision = engine.evaluate("default", "GET", path)
            elapsed_ms = (time.perf_counter() - start) * 1000

            bypassed = elapsed_ms > 5.0
            _record(
                "LogicBomber", "PolicyEngine",
                f"GET (len={len(path)})", f"time={elapsed_ms:.2f}ms effect={decision.effect}",
                bypassed=bypassed,
                latency_ms=elapsed_ms,
                details=f"fnmatch ReDoS: {elapsed_ms:.2f}ms" if bypassed else "Within limits",
            )
            if bypassed:
                pytest.fail(
                    f"VULNERABILITY: fnmatch slow: {elapsed_ms:.2f}ms for path len={len(path)}"
                )

    # ── 2c. Rule priority conflict — privilege escalation ─────────
    # Default policy: explicit deny for POST /calendars/*/events
    # But if the path doesn't match the explicit deny rule (e.g., due to
    # extra segments), it falls through to default_effect=deny anyway.
    # Attack vector: find a path that matches an ALLOW rule but is
    # actually a write operation.

    def test_freebuy_post_escalation(self, client, google_agent):
        """POST /freeBusy is explicitly allowed (it's a read).
        Can we abuse this to sneak other POST requests through?"""
        # The default policy allows POST to /freeBusy specifically.
        # What if we POST to /freeBusy/../calendars/primary/events?
        attack_paths = [
            "/freeBusy/../calendars/primary/events",
            "/freeBusy%2F..%2Fcalendars%2Fprimary%2Fevents",
        ]
        for path in attack_paths:
            resp = client.post(
                f"/proxy/google{path}",
                headers={
                    "X-Agent-Key": google_agent["api_key"],
                    "Content-Type": "application/json",
                },
                content=b'{"summary":"evil"}',
            )
            # If this gets through validation middleware as path traversal, good.
            # If it reaches the proxy and gets allowed, that's a bypass.
            bypassed = resp.status_code == 200
            _record(
                "LogicBomber", "PolicyEngine",
                f"POST /proxy/google{path}", f"status={resp.status_code}",
                bypassed=bypassed,
                details="Priority escalation via freeBusy" if bypassed else "Blocked",
            )

    # ── 2d. fnmatch wildcard boundary — slash semantics ───────────
    # fnmatch * does NOT match '/'. So /calendars/*/events matches
    # /calendars/primary/events but NOT /calendars/primary/sub/events.
    # Can we use this to find gaps?

    def test_fnmatch_slash_boundary(self, client, google_agent):
        """Paths with extra segments should not bypass policy matching."""
        # These paths shouldn't match "/calendars/*/events" because of extra slashes
        gap_paths = [
            "/calendars/primary/sub/events",       # extra segment
            "/calendars/primary/events/extra",      # trailing segment
        ]
        for path in gap_paths:
            mock_resp = httpx.Response(status_code=200, json={"items": []})
            with patch.object(reverse_proxy, "_client") as mock_client:
                mock_client.request = AsyncMock(return_value=mock_resp)
                resp = client.get(
                    f"/proxy/google{path}",
                    headers={"X-Agent-Key": google_agent["api_key"]},
                )
            # These should be denied (no matching allow rule, falls to default deny)
            # If allowed, the default_effect may not be working correctly
            _record(
                "LogicBomber", "PolicyEngine",
                f"GET /proxy/google{path}", f"status={resp.status_code}",
                bypassed=resp.status_code == 200,
                details="fnmatch slash boundary gap" if resp.status_code == 200 else "Correctly denied",
            )

    # ── 2e. Method case sensitivity ───────────────────────────────

    def test_method_case_bypass(self):
        """Mixed-case HTTP methods should be normalized."""
        analyzer = IntentAnalyzer()
        methods = ["get", "Get", "gEt", "GET"]
        for m in methods:
            result = _run(analyzer.analyze(m, "/calendars/primary/events", "google"))
            bypassed = result.intent_type != "read"
            _record(
                "LogicBomber", "IntentAnalyzer",
                f"{m} /calendars/primary/events", f"intent={result.intent_type}",
                bypassed=bypassed,
                details="Method case bypass" if bypassed else "OK",
            )
            # Record — discovery phase


# ═══════════════════════════════════════════════════════════════════════
# Agent 3: The Sniper — Performance / Concurrency Attacks
# ═══════════════════════════════════════════════════════════════════════

class TestSniper:
    """Attack infrastructure: SQLite concurrency, rate limiter memory, log I/O."""

    # ── 3a. Parallel request storm — DB lock contention ───────────

    def test_concurrent_audit_writes(self, client, google_agent):
        """Parallel requests should not cause SQLite lock errors or >5ms latency."""
        import concurrent.futures

        def fire_request():
            start = time.perf_counter()
            resp = client.get(
                "/proxy/google/calendars/primary/events",
                headers={"X-Agent-Key": google_agent["api_key"]},
            )
            elapsed = (time.perf_counter() - start) * 1000
            return resp.status_code, elapsed

        # Even denied requests write to audit DB, so we can use simple denies
        def fire_deny():
            start = time.perf_counter()
            resp = client.delete(
                "/proxy/google/calendars/primary/events/x",
                headers={"X-Agent-Key": google_agent["api_key"]},
            )
            elapsed = (time.perf_counter() - start) * 1000
            return resp.status_code, elapsed

        # Fire 20 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            futures = [pool.submit(fire_deny) for _ in range(20)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        latencies = [r[1] for r in results]
        errors = [r for r in results if r[0] >= 500]
        avg_latency = sum(latencies) / len(latencies)
        max_latency = max(latencies)
        p95_latency = sorted(latencies)[int(len(latencies) * 0.95)]

        bypassed = len(errors) > 0 or p95_latency > 50
        _record(
            "Sniper", "SQLite/AuditDB",
            f"20 concurrent DELETE requests",
            f"errors={len(errors)} avg={avg_latency:.1f}ms p95={p95_latency:.1f}ms max={max_latency:.1f}ms",
            bypassed=bypassed,
            latency_ms=p95_latency,
            details=f"Server errors: {len(errors)}" if errors else "No errors",
        )

    # ── 3b. Rate limiter memory exhaustion ────────────────────────

    def test_rate_limiter_memory_growth(self):
        """Rate limiter should not grow unbounded with many unique agent_ids."""
        from app.rate_limiter import RateLimiter, RateLimitConfig

        limiter = RateLimiter()
        config = RateLimitConfig(requests_per_minute=1000, requests_per_hour=10000)

        # Simulate 1000 different agents making 1 request each
        start = time.perf_counter()
        for i in range(1000):
            limiter.record(f"agent_{i}")
            limiter.check(f"agent_{i}", config)
        elapsed_ms = (time.perf_counter() - start) * 1000

        bypassed = elapsed_ms > 100  # 1000 operations should be fast
        _record(
            "Sniper", "RateLimiter",
            "1000 unique agents x 1 request",
            f"time={elapsed_ms:.2f}ms",
            bypassed=bypassed,
            latency_ms=elapsed_ms,
            details="Memory/performance concern" if bypassed else "Acceptable",
        )

    # ── 3c. Rate limiter with many timestamps per agent ───────────

    def test_rate_limiter_large_window(self):
        """Single agent with many requests should not slow down checks."""
        from app.rate_limiter import RateLimiter, RateLimitConfig

        limiter = RateLimiter()
        # Set high limits so nothing gets rejected
        config = RateLimitConfig(requests_per_minute=100000, requests_per_hour=1000000)

        # Flood a single agent with 10000 timestamps
        for _ in range(10000):
            limiter.record("flood_agent")

        start = time.perf_counter()
        result = limiter.check("flood_agent", config)
        elapsed_ms = (time.perf_counter() - start) * 1000

        bypassed = elapsed_ms > 5.0
        _record(
            "Sniper", "RateLimiter",
            "check() after 10000 timestamps",
            f"time={elapsed_ms:.2f}ms allowed={result.allowed}",
            bypassed=bypassed,
            latency_ms=elapsed_ms,
            details="Slow window scan" if bypassed else "OK",
        )
        # Record — discovery phase

    # ── 3d. Long path stress — does path processing stay <5ms? ────

    def test_long_path_processing_time(self, client, google_agent):
        """Extremely long paths should not cause processing delay >5ms."""
        long_path = "/calendars/" + "a" * 10000 + "/events"
        start = time.perf_counter()
        resp = client.get(
            f"/proxy/google{long_path}",
            headers={"X-Agent-Key": google_agent["api_key"]},
        )
        elapsed_ms = (time.perf_counter() - start) * 1000

        bypassed = elapsed_ms > 50  # generous threshold for e2e
        _record(
            "Sniper", "Proxy/FullStack",
            f"GET path_len={len(long_path)}",
            f"time={elapsed_ms:.2f}ms status={resp.status_code}",
            bypassed=bypassed,
            latency_ms=elapsed_ms,
            details="Long path perf issue" if bypassed else "OK",
        )

    # ── 3e. Rapid sequential requests — connection exhaustion ─────

    def test_rapid_sequential_requests(self, client, google_agent):
        """100 rapid sequential requests should all succeed without errors."""
        errors = 0
        latencies = []
        for _ in range(100):
            start = time.perf_counter()
            resp = client.delete(
                "/proxy/google/calendars/primary/events/x",
                headers={"X-Agent-Key": google_agent["api_key"]},
            )
            elapsed = (time.perf_counter() - start) * 1000
            latencies.append(elapsed)
            if resp.status_code >= 500:
                errors += 1

        avg = sum(latencies) / len(latencies)
        p99 = sorted(latencies)[99]
        _record(
            "Sniper", "Proxy/Sequential",
            "100 rapid sequential DELETEs",
            f"errors={errors} avg={avg:.1f}ms p99={p99:.1f}ms",
            bypassed=errors > 0,
            latency_ms=p99,
            details=f"{errors} server errors" if errors else "All handled",
        )


# ═══════════════════════════════════════════════════════════════════════
# Report Generation — runs after all tests
# ═══════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="session", autouse=True)
def write_vulnerability_report():
    """Write vulnerability_report.json after all GateBreaker tests complete."""
    yield
    if _findings:
        report = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_attacks": len(_findings),
            "bypasses_found": sum(1 for f in _findings if f["bypassed"]),
            "findings": _findings,
        }
        REPORT_PATH.write_text(json.dumps(report, indent=2, ensure_ascii=False))
