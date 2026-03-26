"""Webhook notifier — sends alerts on deny/rate_limit events."""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import httpx
from loguru import logger


@dataclass
class WebhookConfig:
    """Webhook configuration."""

    url: str
    events: list[str] = field(default_factory=lambda: ["deny", "rate_limited"])
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class AlertThreshold:
    """Threshold-based alert: fires when count exceeds limit within window."""

    event: str = "deny"
    count: int = 10
    window_seconds: int = 300  # 5 minutes
    agent_id: str | None = None  # None = all agents


class WebhookNotifier:
    """Sends webhook notifications for proxy events and threshold alerts."""

    def __init__(self) -> None:
        self._webhooks: list[WebhookConfig] = []
        self._thresholds: list[AlertThreshold] = []
        self._event_log: dict[str, list[float]] = defaultdict(list)
        self._client: httpx.AsyncClient | None = None
        self._fired_alerts: dict[str, float] = {}  # cooldown tracking

    def add_webhook(self, config: WebhookConfig) -> None:
        self._webhooks.append(config)
        logger.info(f"Webhook registered: {config.url} for events={config.events}")

    def add_threshold(self, threshold: AlertThreshold) -> None:
        self._thresholds.append(threshold)
        logger.info(
            f"Alert threshold: {threshold.count} {threshold.event}s "
            f"in {threshold.window_seconds}s"
        )

    async def notify(self, event: str, payload: dict[str, Any]) -> None:
        """Send webhook for matching event and check thresholds."""
        # Record event for threshold tracking
        agent_id = payload.get("agent_id", "")
        key = f"{event}:{agent_id}"
        self._event_log[key].append(time.monotonic())

        # Send webhooks for matching events
        for wh in self._webhooks:
            if event in wh.events:
                await self._send(wh, event, payload)

        # Check thresholds
        await self._check_thresholds(event, agent_id, payload)

    async def _check_thresholds(
        self, event: str, agent_id: str, payload: dict[str, Any]
    ) -> None:
        now = time.monotonic()
        for threshold in self._thresholds:
            if threshold.event != event:
                continue
            if threshold.agent_id and threshold.agent_id != agent_id:
                continue

            key = f"{event}:{agent_id}" if threshold.agent_id else f"{event}:*"

            # Count events in window
            if threshold.agent_id:
                timestamps = self._event_log.get(f"{event}:{agent_id}", [])
            else:
                # Count across all agents
                timestamps = []
                for k, v in self._event_log.items():
                    if k.startswith(f"{event}:"):
                        timestamps.extend(v)

            cutoff = now - threshold.window_seconds
            recent = [t for t in timestamps if t > cutoff]

            if len(recent) >= threshold.count:
                # Cooldown: don't fire the same alert within the window
                alert_key = f"alert:{key}:{threshold.count}"
                last_fired = self._fired_alerts.get(alert_key, 0)
                if now - last_fired < threshold.window_seconds:
                    continue

                self._fired_alerts[alert_key] = now
                alert_payload = {
                    "alert": "threshold_exceeded",
                    "event": event,
                    "count": len(recent),
                    "threshold": threshold.count,
                    "window_seconds": threshold.window_seconds,
                    "agent_id": agent_id or "all",
                    "latest_event": payload,
                }
                for wh in self._webhooks:
                    await self._send(wh, "alert", alert_payload)

    async def _send(
        self, wh: WebhookConfig, event: str, payload: dict[str, Any]
    ) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=10.0)

        body = {"event": event, "data": payload}
        try:
            resp = await self._client.post(wh.url, json=body, headers=wh.headers)
            if resp.status_code >= 400:
                logger.warning(
                    f"Webhook {wh.url} returned {resp.status_code}: {resp.text[:200]}"
                )
        except httpx.RequestError as exc:
            logger.error(f"Webhook delivery failed to {wh.url}: {exc}")

    def prune_event_log(self, max_age_seconds: int = 600) -> None:
        """Remove old entries from event log to prevent memory growth."""
        cutoff = time.monotonic() - max_age_seconds
        for key in list(self._event_log.keys()):
            self._event_log[key] = [t for t in self._event_log[key] if t > cutoff]
            if not self._event_log[key]:
                del self._event_log[key]

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
