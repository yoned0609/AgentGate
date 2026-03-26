"""Tests for request validation middleware and provider mismatch check."""

import pytest
from fastapi.testclient import TestClient

from app.main import app, settings


MASTER_KEY = settings.master_api_key


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def google_agent(client):
    """Create a test agent for google provider via API."""
    resp = client.post(
        "/agents",
        json={
            "name": "test-validation-google",
            "policy": "default",
            "provider": "google",
        },
        headers={"X-Master-Key": MASTER_KEY},
    )
    agent = resp.json()
    yield agent
    client.delete(f"/agents/{agent['agent_id']}", headers={"X-Master-Key": MASTER_KEY})


class TestPathTraversal:
    def test_blocks_encoded_dot_dot_slash(self, client):
        """Test URL-encoded path traversal."""
        resp = client.get("/proxy/google/%2e%2e/secret")
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_path"

    def test_blocks_double_encoded_traversal(self, client):
        resp = client.get("/proxy/google/%252e%252e/secret")
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_path"

    def test_blocks_null_byte(self, client):
        resp = client.get("/proxy/google/calendars%00.json")
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_path"

    def test_allows_normal_path(self, client, google_agent):
        resp = client.get(
            "/proxy/google/calendars/primary/events",
            headers={"X-Agent-Key": google_agent["api_key"]},
        )
        assert resp.status_code != 400


class TestBodySize:
    def test_blocks_oversized_body(self, client, google_agent):
        resp = client.post(
            "/proxy/google/calendars/primary/events",
            headers={
                "X-Agent-Key": google_agent["api_key"],
                "Content-Length": "2000000",
                "Content-Type": "application/json",
            },
            content=b"x",
        )
        assert resp.status_code == 413
        assert resp.json()["error"] == "body_too_large"


class TestProviderMismatch:
    def test_blocks_wrong_provider(self, client, google_agent):
        """Google agent should not access Slack endpoints."""
        resp = client.get(
            "/proxy/slack/conversations.list",
            headers={"X-Agent-Key": google_agent["api_key"]},
        )
        assert resp.status_code == 403
        assert resp.json()["error"] == "provider_mismatch"

    def test_allows_correct_provider(self, client, google_agent):
        """Google agent accessing Google should not get provider_mismatch."""
        resp = client.post(
            "/proxy/google/calendars/primary/events",
            headers={
                "X-Agent-Key": google_agent["api_key"],
                "Content-Type": "application/json",
            },
            content=b'{"summary": "test"}',
        )
        assert resp.status_code == 403
        assert resp.json()["error"] == "access_denied"
