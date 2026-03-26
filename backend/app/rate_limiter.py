"""Rate limiter — sliding window counter per agent."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class RateLimitConfig:
    """Rate limit configuration from policy YAML."""

    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    enabled: bool = True


@dataclass
class _WindowCounter:
    """Sliding window counter for a single agent."""

    timestamps: list[float] = field(default_factory=list)

    def count_within(self, window_seconds: float) -> int:
        """Count requests within the last N seconds, pruning old entries."""
        cutoff = time.monotonic() - window_seconds
        self.timestamps = [t for t in self.timestamps if t > cutoff]
        return len(self.timestamps)

    def record(self) -> None:
        self.timestamps.append(time.monotonic())


@dataclass
class RateLimitResult:
    allowed: bool
    retry_after: int | None = None
    limit: int = 0
    remaining: int = 0
    window: str = ""


class RateLimiter:
    """In-memory sliding window rate limiter keyed by agent_id."""

    def __init__(self) -> None:
        self._counters: dict[str, _WindowCounter] = {}

    def check(self, agent_id: str, config: RateLimitConfig) -> RateLimitResult:
        """Check if the agent is within rate limits. Does NOT record the request."""
        if not config.enabled:
            return RateLimitResult(allowed=True)

        counter = self._counters.setdefault(agent_id, _WindowCounter())

        # Check per-minute limit first (stricter window)
        minute_count = counter.count_within(60)
        if minute_count >= config.requests_per_minute:
            return RateLimitResult(
                allowed=False,
                retry_after=self._retry_after(counter, 60),
                limit=config.requests_per_minute,
                remaining=0,
                window="1m",
            )

        # Check per-hour limit
        hour_count = counter.count_within(3600)
        if hour_count >= config.requests_per_hour:
            return RateLimitResult(
                allowed=False,
                retry_after=self._retry_after(counter, 3600),
                limit=config.requests_per_hour,
                remaining=0,
                window="1h",
            )

        return RateLimitResult(
            allowed=True,
            limit=config.requests_per_minute,
            remaining=config.requests_per_minute - minute_count - 1,
            window="1m",
        )

    def record(self, agent_id: str) -> None:
        """Record a request for the agent."""
        counter = self._counters.setdefault(agent_id, _WindowCounter())
        counter.record()

    @staticmethod
    def _retry_after(counter: _WindowCounter, window_seconds: float) -> int:
        """Calculate seconds until the oldest request in the window expires."""
        if not counter.timestamps:
            return 1
        cutoff = time.monotonic() - window_seconds
        oldest_in_window = min(t for t in counter.timestamps if t > cutoff)
        wait = oldest_in_window + window_seconds - time.monotonic()
        return max(1, int(wait) + 1)
