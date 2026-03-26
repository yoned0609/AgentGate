"""Agent registry — SQLite-backed store with key rotation and usage stats."""

from __future__ import annotations

import json
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite
from loguru import logger

AgentDict = dict[str, Any]

_CREATE_AGENTS_TABLE = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    api_key TEXT NOT NULL UNIQUE,
    policy TEXT NOT NULL DEFAULT 'default',
    provider TEXT NOT NULL DEFAULT 'google',
    created_at TEXT NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    deny_count INTEGER NOT NULL DEFAULT 0,
    last_request_at TEXT
);
"""

_CREATE_KEY_INDEX = """
CREATE INDEX IF NOT EXISTS idx_agents_api_key ON agents(api_key);
"""

_MIGRATIONS = [
    "ALTER TABLE agents ADD COLUMN request_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE agents ADD COLUMN deny_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE agents ADD COLUMN last_request_at TEXT",
]


def _generate_api_key() -> str:
    """Generate a cryptographically secure API key with 'ag_' prefix."""
    return f"ag_{secrets.token_hex(24)}"


class AgentStore:
    """SQLite-backed agent registry with key rotation and usage tracking."""

    def __init__(self, db_path: str = "agents.db") -> None:
        self._db_path = db_path
        self._initialized = False
        self._cache: dict[str, AgentDict] = {}
        self._key_cache: dict[str, str] = {}  # api_key -> agent_id
        self._legacy_json = Path("agents.json")

    async def _ensure_init(self) -> None:
        if self._initialized:
            return
        async with aiosqlite.connect(self._db_path) as db:
            await db.executescript(_CREATE_AGENTS_TABLE + _CREATE_KEY_INDEX)
            for migration in _MIGRATIONS:
                try:
                    await db.execute(migration)
                except Exception:
                    pass
            await db.commit()

        await self._migrate_from_json()
        await self._refresh_cache()
        self._initialized = True
        logger.info(
            f"Agent store initialized: {self._db_path} ({len(self._cache)} agents)"
        )

    async def _migrate_from_json(self) -> None:
        """One-time migration from agents.json to SQLite."""
        if not self._legacy_json.exists():
            return
        try:
            async with aiosqlite.connect(self._db_path) as db:
                cursor = await db.execute("SELECT COUNT(*) FROM agents")
                row = await cursor.fetchone()
                if row and row[0] > 0:
                    return

            data = json.loads(self._legacy_json.read_text(encoding="utf-8"))
            async with aiosqlite.connect(self._db_path) as db:
                for agent in data.values():
                    await db.execute(
                        """INSERT OR IGNORE INTO agents
                           (agent_id, name, description, api_key, policy, provider, created_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (
                            agent["agent_id"],
                            agent["name"],
                            agent.get("description", ""),
                            agent["api_key"],
                            agent.get("policy", "default"),
                            agent.get("provider", "google"),
                            agent.get(
                                "created_at",
                                datetime.now(timezone.utc).isoformat(),
                            ),
                        ),
                    )
                await db.commit()
            logger.info(f"Migrated {len(data)} agents from {self._legacy_json}")
            self._legacy_json.rename(self._legacy_json.with_suffix(".json.bak"))
        except Exception as e:
            logger.error(f"Failed to migrate from JSON: {e}")

    async def _refresh_cache(self) -> None:
        """Reload in-memory cache from SQLite."""
        self._cache.clear()
        self._key_cache.clear()
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM agents")
            rows = await cursor.fetchall()
            for row in rows:
                agent = dict(row)
                self._cache[agent["agent_id"]] = agent
                self._key_cache[agent["api_key"]] = agent["agent_id"]

    async def create(
        self,
        name: str,
        description: str = "",
        policy: str = "default",
        provider: str = "google",
    ) -> AgentDict:
        """Register a new agent."""
        await self._ensure_init()
        agent_id = str(uuid.uuid4())
        api_key = _generate_api_key()
        created_at = datetime.now(timezone.utc).isoformat()

        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """INSERT INTO agents
                   (agent_id, name, description, api_key, policy, provider, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (agent_id, name, description, api_key, policy, provider, created_at),
            )
            await db.commit()

        agent: AgentDict = {
            "agent_id": agent_id,
            "name": name,
            "description": description,
            "api_key": api_key,
            "policy": policy,
            "provider": provider,
            "created_at": created_at,
            "request_count": 0,
            "deny_count": 0,
            "last_request_at": None,
        }
        self._cache[agent_id] = agent
        self._key_cache[api_key] = agent_id
        logger.info(f"Agent created: {name} ({agent_id}), policy={policy}")
        return agent

    def get_by_api_key(self, api_key: str) -> AgentDict | None:
        """Look up an agent by its API key (O(1) via cache)."""
        agent_id = self._key_cache.get(api_key)
        if agent_id:
            return self._cache.get(agent_id)
        return None

    def get_by_id(self, agent_id: str) -> AgentDict | None:
        """Look up an agent by its unique ID."""
        return self._cache.get(agent_id)

    def list_all(self) -> list[AgentDict]:
        """Return all registered agents."""
        return list(self._cache.values())

    async def delete(self, agent_id: str) -> bool:
        """Remove an agent."""
        await self._ensure_init()
        if agent_id not in self._cache:
            return False

        agent = self._cache.pop(agent_id)
        self._key_cache.pop(agent["api_key"], None)

        async with aiosqlite.connect(self._db_path) as db:
            await db.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
            await db.commit()
        return True

    async def rotate_key(self, agent_id: str) -> AgentDict | None:
        """Generate a new API key for an agent. Returns updated agent or None."""
        await self._ensure_init()
        agent = self._cache.get(agent_id)
        if agent is None:
            return None

        old_key = agent["api_key"]
        new_key = _generate_api_key()

        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "UPDATE agents SET api_key = ? WHERE agent_id = ?",
                (new_key, agent_id),
            )
            await db.commit()

        self._key_cache.pop(old_key, None)
        agent["api_key"] = new_key
        self._key_cache[new_key] = agent_id
        logger.info(f"API key rotated for agent {agent['name']} ({agent_id})")
        return agent

    async def record_request(self, agent_id: str, denied: bool = False) -> None:
        """Increment request/deny counters for usage stats."""
        await self._ensure_init()
        agent = self._cache.get(agent_id)
        if agent is None:
            return

        now = datetime.now(timezone.utc).isoformat()
        agent["request_count"] = agent.get("request_count", 0) + 1
        agent["last_request_at"] = now
        if denied:
            agent["deny_count"] = agent.get("deny_count", 0) + 1

        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """UPDATE agents SET request_count = request_count + 1,
                   deny_count = deny_count + ?,
                   last_request_at = ?
                   WHERE agent_id = ?""",
                (1 if denied else 0, now, agent_id),
            )
            await db.commit()

    async def get_stats(self, agent_id: str) -> dict[str, Any] | None:
        """Get usage statistics for an agent."""
        await self._ensure_init()
        agent = self._cache.get(agent_id)
        if agent is None:
            return None
        req_count = agent.get("request_count", 0)
        return {
            "agent_id": agent_id,
            "name": agent["name"],
            "request_count": req_count,
            "deny_count": agent.get("deny_count", 0),
            "deny_rate": (
                agent.get("deny_count", 0) / req_count if req_count > 0 else 0.0
            ),
            "last_request_at": agent.get("last_request_at"),
        }

    @property
    def count(self) -> int:
        return len(self._cache)
