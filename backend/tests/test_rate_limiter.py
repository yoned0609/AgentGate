"""Tests for rate limiter module."""

import time

from app.rate_limiter import RateLimitConfig, RateLimiter, _WindowCounter


class TestRateLimiter:
    def setup_method(self):
        self.limiter = RateLimiter()
        self.config = RateLimitConfig(
            requests_per_minute=5,
            requests_per_hour=100,
            enabled=True,
        )

    def test_allows_within_limit(self):
        for _ in range(4):
            result = self.limiter.check("agent-1", self.config)
            assert result.allowed
            self.limiter.record("agent-1")

    def test_denies_when_minute_limit_exceeded(self):
        for _ in range(5):
            self.limiter.record("agent-1")

        result = self.limiter.check("agent-1", self.config)
        assert not result.allowed
        assert result.retry_after is not None
        assert result.retry_after >= 1
        assert result.window == "1m"

    def test_separate_agents_have_separate_limits(self):
        for _ in range(5):
            self.limiter.record("agent-1")

        # agent-2 should still be allowed
        result = self.limiter.check("agent-2", self.config)
        assert result.allowed

    def test_disabled_config_always_allows(self):
        disabled = RateLimitConfig(enabled=False)
        for _ in range(100):
            self.limiter.record("agent-1")

        result = self.limiter.check("agent-1", disabled)
        assert result.allowed

    def test_remaining_count_decreases(self):
        result = self.limiter.check("agent-1", self.config)
        assert result.remaining == 4  # 5 - 0 - 1

        self.limiter.record("agent-1")
        result = self.limiter.check("agent-1", self.config)
        assert result.remaining == 3  # 5 - 1 - 1

    def test_hour_limit_exceeded(self):
        hour_config = RateLimitConfig(
            requests_per_minute=1000,
            requests_per_hour=3,
            enabled=True,
        )
        for _ in range(3):
            self.limiter.record("agent-1")

        result = self.limiter.check("agent-1", hour_config)
        assert not result.allowed
        assert result.window == "1h"

    def test_window_expires(self):
        """Requests outside the window should not count."""
        counter = _WindowCounter()
        past = time.monotonic() - 120  # 2 minutes ago
        counter.timestamps = [past + i for i in range(5)]
        self.limiter._counters["agent-1"] = counter

        result = self.limiter.check("agent-1", self.config)
        assert result.allowed  # Old timestamps pruned
