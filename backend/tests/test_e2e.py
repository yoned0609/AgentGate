"""End-to-end integration tests — full proxy flow with mocked upstream."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app, reverse_proxy, settings

MASTER_KEY = settings.master_api_key
HEADERS_MASTER = {"X-Master-Key": MASTER_KEY}


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def google_agent(client):
    resp = client.post(
        "/agents",
        json={"name": "e2e-google", "policy": "default", "provider": "google"},
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
        json={"name": "e2e-rw", "policy": "readwrite", "provider": "google"},
        headers=HEADERS_MASTER,
    )
    assert resp.status_code == 200
    agent = resp.json()
    yield agent
    client.delete(f"/agents/{agent['agent_id']}", headers=HEADERS_MASTER)


def _mock_upstream_response(status_code=200, json_body=None, headers=None):
    """Create a mock httpx.Response."""
    body = json_body or {"items": []}
    return httpx.Response(
        status_code=status_code,
        json=body,
        headers=headers or {},
    )


# ── Full proxy allow flow ───────────────────────────────────────────


class TestProxyAllowFlow:
    def test_get_events_allowed_and_forwarded(self, client, google_agent):
        """GET calendar events: auth → intent → policy(allow) → forward → audit."""
        mock_resp = _mock_upstream_response(200, {"items": [{"id": "evt1"}]})
        with patch.object(reverse_proxy, "_client") as mock_client:
            mock_client.request = AsyncMock(return_value=mock_resp)
            resp = client.get(
                "/proxy/google/calendars/primary/events",
                headers={
                    "X-Agent-Key": google_agent["api_key"],
                    "Authorization": "Bearer fake-token",
                },
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["items"][0]["id"] == "evt1"

    def test_forwarded_response_preserves_status(self, client, google_agent):
        """Upstream 404 should be passed through."""
        mock_resp = _mock_upstream_response(404, {"error": "not_found"})
        with patch.object(reverse_proxy, "_client") as mock_client:
            mock_client.request = AsyncMock(return_value=mock_resp)
            resp = client.get(
                "/proxy/google/calendars/primary/events/nonexistent",
                headers={"X-Agent-Key": google_agent["api_key"]},
            )

        assert resp.status_code == 404


# ── Policy deny flow ────────────────────────────────────────────────


class TestProxyDenyFlow:
    def test_post_denied_by_default_policy(self, client, google_agent):
        """POST to events: default policy denies write → 403 with structured response."""
        resp = client.post(
            "/proxy/google/calendars/primary/events",
            headers={
                "X-Agent-Key": google_agent["api_key"],
                "Content-Type": "application/json",
            },
            content=b'{"summary": "meeting"}',
        )

        assert resp.status_code == 403
        data = resp.json()
        assert data["error"] == "access_denied"
        assert "intent" in data
        assert data["intent"]["type"] == "create"
        assert "suggestion" in data
        assert "request_id" in data

    def test_delete_denied_with_reason(self, client, google_agent):
        """DELETE: denied with specific reason from policy."""
        resp = client.delete(
            "/proxy/google/calendars/primary/events/abc123",
            headers={"X-Agent-Key": google_agent["api_key"]},
        )

        assert resp.status_code == 403
        data = resp.json()
        assert data["intent"]["type"] == "delete"

    def test_readwrite_allows_post_but_denies_delete(self, client, rw_agent):
        """readwrite policy: POST allowed, DELETE denied."""
        # POST should be allowed (will fail at upstream but policy passes)
        mock_resp = _mock_upstream_response(201, {"id": "new_event"})
        with patch.object(reverse_proxy, "_client") as mock_client:
            mock_client.request = AsyncMock(return_value=mock_resp)
            resp = client.post(
                "/proxy/google/calendars/primary/events",
                headers={
                    "X-Agent-Key": rw_agent["api_key"],
                    "Content-Type": "application/json",
                },
                content=b'{"summary": "meeting"}',
            )
        assert resp.status_code == 201

        # DELETE should be denied
        resp = client.delete(
            "/proxy/google/calendars/primary/events/abc",
            headers={"X-Agent-Key": rw_agent["api_key"]},
        )
        assert resp.status_code == 403


# ── Auth flow ───────────────────────────────────────────────────────


class TestAuthFlow:
    def test_missing_agent_key_returns_401(self, client):
        resp = client.get("/proxy/google/calendars/primary/events")
        assert resp.status_code == 401

    def test_invalid_agent_key_returns_401(self, client):
        resp = client.get(
            "/proxy/google/calendars/primary/events",
            headers={"X-Agent-Key": "ag_invalid_key"},
        )
        assert resp.status_code == 401

    def test_provider_mismatch_returns_403(self, client, google_agent):
        """Google agent cannot access Slack."""
        resp = client.get(
            "/proxy/slack/conversations.list",
            headers={"X-Agent-Key": google_agent["api_key"]},
        )
        assert resp.status_code == 403
        assert resp.json()["error"] == "provider_mismatch"


# ── Audit log verification ──────────────────────────────────────────


class TestAuditIntegration:
    def test_allow_creates_audit_entry(self, client, google_agent):
        """Allowed requests should appear in audit logs."""
        mock_resp = _mock_upstream_response(200, {"items": []})
        with patch.object(reverse_proxy, "_client") as mock_client:
            mock_client.request = AsyncMock(return_value=mock_resp)
            client.get(
                "/proxy/google/calendars/primary/events",
                headers={"X-Agent-Key": google_agent["api_key"]},
            )

        # Check audit log
        resp = client.get(
            f"/audit/logs?agent_id={google_agent['agent_id']}&decision=allow",
            headers=HEADERS_MASTER,
        )
        data = resp.json()
        assert data["total"] >= 1
        log = data["logs"][0]
        assert log["decision"] == "allow"
        assert log["method"] == "GET"
        assert log["provider"] == "google"

    def test_deny_creates_audit_entry(self, client, google_agent):
        """Denied requests should appear in audit logs."""
        client.delete(
            "/proxy/google/calendars/primary/events/abc",
            headers={"X-Agent-Key": google_agent["api_key"]},
        )

        resp = client.get(
            f"/audit/logs?agent_id={google_agent['agent_id']}&decision=deny",
            headers=HEADERS_MASTER,
        )
        data = resp.json()
        assert data["total"] >= 1
        assert data["logs"][0]["decision"] == "deny"

    def test_audit_stats_endpoint(self, client, google_agent):
        """Stats endpoint should return aggregated data."""
        # Generate some traffic
        client.delete(
            "/proxy/google/calendars/primary/events/x",
            headers={"X-Agent-Key": google_agent["api_key"]},
        )

        resp = client.get("/audit/stats", headers=HEADERS_MASTER)
        assert resp.status_code == 200
        data = resp.json()
        assert "total_requests" in data
        assert "by_decision" in data
        assert "deny_rate" in data
        assert "avg_latency_ms" in data


# ── Agent management flow ───────────────────────────────────────────


class TestAgentManagement:
    def test_create_list_delete_flow(self, client):
        """Full agent lifecycle: create → list → stats → rotate key → delete."""
        # Create
        resp = client.post(
            "/agents",
            json={"name": "lifecycle-test", "policy": "default", "provider": "google"},
            headers=HEADERS_MASTER,
        )
        assert resp.status_code == 200
        agent = resp.json()
        agent_id = agent["agent_id"]
        original_key = agent["api_key"]

        # List
        resp = client.get("/agents", headers=HEADERS_MASTER)
        names = [a["name"] for a in resp.json()]
        assert "lifecycle-test" in names

        # Stats
        resp = client.get(f"/agents/{agent_id}/stats", headers=HEADERS_MASTER)
        assert resp.status_code == 200
        assert resp.json()["request_count"] == 0

        # Rotate key
        resp = client.post(f"/agents/{agent_id}/rotate-key", headers=HEADERS_MASTER)
        assert resp.status_code == 200
        new_key = resp.json()["api_key"]
        assert new_key != original_key

        # Old key should no longer work
        resp = client.get(
            "/proxy/google/calendars/primary/events",
            headers={"X-Agent-Key": original_key},
        )
        assert resp.status_code == 401

        # New key should work (will hit policy, not auth error)
        resp = client.delete(
            "/proxy/google/calendars/primary/events/x",
            headers={"X-Agent-Key": new_key},
        )
        assert resp.status_code == 403  # Policy deny, not 401

        # Delete
        resp = client.delete(f"/agents/{agent_id}", headers=HEADERS_MASTER)
        assert resp.status_code == 200

    def test_create_with_invalid_policy_fails(self, client):
        resp = client.post(
            "/agents",
            json={"name": "bad", "policy": "nonexistent"},
            headers=HEADERS_MASTER,
        )
        assert resp.status_code == 400

    def test_admin_endpoints_require_master_key(self, client):
        """All admin endpoints should reject requests without master key."""
        assert client.get("/agents").status_code == 403
        assert client.get("/audit/logs").status_code == 403
        assert client.get("/policies").status_code == 403


# ── Webhook registration flow ───────────────────────────────────────


class TestWebhookRegistration:
    def test_register_webhook(self, client):
        resp = client.post(
            "/webhooks",
            json={"url": "http://example.com/hook", "events": ["deny"]},
            headers=HEADERS_MASTER,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "registered"

    def test_register_alert_threshold(self, client):
        resp = client.post(
            "/alerts/thresholds",
            json={"event": "deny", "count": 5, "window_seconds": 300},
            headers=HEADERS_MASTER,
        )
        assert resp.status_code == 200
        assert resp.json()["count"] == 5


# ── Health + discovery ──────────────────────────────────────────────


class TestHealthAndDiscovery:
    def test_health_endpoint(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("ok", "degraded")
        assert "providers" in data

    def test_root_endpoint(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.json()["service"] == "AgentGate"

    def test_providers_endpoint(self, client):
        resp = client.get("/providers")
        assert resp.status_code == 200
        providers = resp.json()["providers"]
        assert "google" in providers
        assert "microsoft" in providers
        assert "slack" in providers

    def test_policies_endpoint(self, client):
        resp = client.get("/policies", headers=HEADERS_MASTER)
        assert resp.status_code == 200
        names = [p["name"] for p in resp.json()]
        assert "default" in names
        assert "readwrite" in names
