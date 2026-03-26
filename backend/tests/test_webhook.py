"""Tests for webhook notifier and threshold alerts."""

import time
from unittest.mock import AsyncMock, patch

import pytest

from app.webhook import AlertThreshold, WebhookConfig, WebhookNotifier


@pytest.fixture
def notifier():
    return WebhookNotifier()


class TestWebhookNotifier:
    @pytest.mark.asyncio
    async def test_notify_sends_to_matching_webhook(self, notifier):
        notifier.add_webhook(
            WebhookConfig(url="http://example.com/hook", events=["deny"])
        )

        with patch.object(notifier, "_send", new_callable=AsyncMock) as mock_send:
            await notifier.notify("deny", {"agent_id": "a1", "reason": "blocked"})
            mock_send.assert_called_once()
            args = mock_send.call_args
            assert args[0][1] == "deny"

    @pytest.mark.asyncio
    async def test_notify_skips_non_matching_event(self, notifier):
        notifier.add_webhook(
            WebhookConfig(url="http://example.com/hook", events=["deny"])
        )

        with patch.object(notifier, "_send", new_callable=AsyncMock) as mock_send:
            await notifier.notify("allow", {"agent_id": "a1"})
            mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_threshold_fires_alert(self, notifier):
        notifier.add_webhook(
            WebhookConfig(url="http://example.com/hook", events=["deny", "alert"])
        )
        notifier.add_threshold(AlertThreshold(event="deny", count=3, window_seconds=60))

        with patch.object(notifier, "_send", new_callable=AsyncMock) as mock_send:
            for i in range(3):
                await notifier.notify("deny", {"agent_id": "a1", "request_id": str(i)})

            # 3 deny sends + 1 alert send = 4 total calls
            assert mock_send.call_count == 4
            # Last call should be the alert
            last_call = mock_send.call_args_list[-1]
            assert last_call[0][1] == "alert"

    @pytest.mark.asyncio
    async def test_threshold_cooldown_prevents_repeat(self, notifier):
        notifier.add_webhook(
            WebhookConfig(url="http://example.com/hook", events=["deny", "alert"])
        )
        notifier.add_threshold(AlertThreshold(event="deny", count=2, window_seconds=60))

        with patch.object(notifier, "_send", new_callable=AsyncMock) as mock_send:
            # First batch: triggers alert
            for i in range(3):
                await notifier.notify("deny", {"agent_id": "a1", "request_id": str(i)})

            alert_count = sum(
                1 for call in mock_send.call_args_list if call[0][1] == "alert"
            )
            assert alert_count == 1  # Only one alert despite 3 denies

    @pytest.mark.asyncio
    async def test_agent_specific_threshold(self, notifier):
        notifier.add_webhook(
            WebhookConfig(url="http://example.com/hook", events=["deny", "alert"])
        )
        notifier.add_threshold(
            AlertThreshold(event="deny", count=2, window_seconds=60, agent_id="a1")
        )

        with patch.object(notifier, "_send", new_callable=AsyncMock) as mock_send:
            # Denies from a2 should not trigger the a1 threshold
            await notifier.notify("deny", {"agent_id": "a2", "request_id": "1"})
            await notifier.notify("deny", {"agent_id": "a2", "request_id": "2"})

            alert_count = sum(
                1 for call in mock_send.call_args_list if call[0][1] == "alert"
            )
            assert alert_count == 0

    def test_prune_event_log(self, notifier):
        now = time.monotonic()
        notifier._event_log["deny:a1"] = [now - 700, now - 650, now - 100]
        notifier.prune_event_log(max_age_seconds=600)

        # Only the entry within 600s should remain
        assert len(notifier._event_log["deny:a1"]) == 1
