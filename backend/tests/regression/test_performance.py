"""Regression tests: Performance constraints.

Generated from vulnerability_report.json — GateBreaker Phase 1.

Vulnerabilities covered:
- VR-008: Concurrent audit writes cause high latency (p95=2219ms)
- VR-009: Long paths (10000 chars) cause 413ms processing time
"""

from __future__ import annotations

import asyncio
import time

import pytest

from app.intent import IntentAnalyzer
from app.policy import PolicyEngine


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestIntentPerformance:
    """Intent analysis must stay <5ms even for adversarial inputs."""

    @pytest.mark.parametrize("path_len", [1000, 5000, 10000])
    def test_long_path_intent_under_5ms(self, path_len):
        analyzer = IntentAnalyzer()
        path = "/calendars/" + "a" * path_len + "/events"
        start = time.perf_counter()
        _run(analyzer.analyze("GET", path, "google"))
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 5.0, f"Intent analysis took {elapsed_ms:.2f}ms for path len={path_len}"

    def test_redos_resistant_patterns(self):
        """Patterns with nested quantifiers should not cause catastrophic backtracking."""
        analyzer = IntentAnalyzer()
        evil_paths = [
            "/calendars/" + "a/b" * 500 + "/events/" + "c/d" * 500,
            "/calendars/" + "/".join(["a"] * 200) + "/events",
        ]
        for path in evil_paths:
            start = time.perf_counter()
            _run(analyzer.analyze("GET", path, "google"))
            elapsed_ms = (time.perf_counter() - start) * 1000
            assert elapsed_ms < 5.0, f"ReDoS: {elapsed_ms:.2f}ms for path len={len(path)}"


class TestPolicyPerformance:
    """Policy evaluation must stay <5ms even for adversarial inputs."""

    @pytest.mark.parametrize("path_len", [1000, 5000, 10000])
    def test_long_path_policy_under_5ms(self, path_len):
        engine = PolicyEngine(policy_dir="policies")
        path = "/calendars/" + "a" * path_len + "/events"
        start = time.perf_counter()
        engine.evaluate("default", "GET", path)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 5.0, f"Policy eval took {elapsed_ms:.2f}ms for path len={path_len}"


class TestPathLengthLimit:
    """Paths exceeding a safe maximum should be rejected early."""

    def test_max_path_length_enforced_by_middleware(self):
        """Paths over 2048 characters should be rejected with 414."""
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app)
        long_path = "/proxy/google/calendars/" + "a" * 3000 + "/events"
        resp = client.get(long_path)
        assert resp.status_code == 414

    def test_normalize_truncates_long_paths(self):
        """normalize_path should truncate excessively long paths."""
        from app.path_normalize import normalize_path
        long_path = "/calendars/" + "a" * 3000 + "/events"
        normalized = normalize_path(long_path)
        assert len(normalized) <= 2048
