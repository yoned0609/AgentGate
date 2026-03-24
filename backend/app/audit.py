"""Audit logger — records all proxy decisions to SQLite."""

from __future__ import annotations

from typing import Any

import aiosqlite
from loguru import logger

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    agent_id TEXT NOT NULL,
    agent_name TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    decision TEXT NOT NULL,
    deny_reason TEXT,
    status_code INTEGER,
    latency_ms REAL NOT NULL DEFAULT 0,
    request_id TEXT NOT NULL
);
"""

_CREATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_logs(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
"""


class AuditLogger:
    """Async SQLite-backed audit log."""

    def __init__(self, db_path: str = "audit.db") -> None:
        self._db_path = db_path
        self._initialized = False

    async def _ensure_init(self) -> None:
        if self._initialized:
            return
        async with aiosqlite.connect(self._db_path) as db:
            await db.executescript(_CREATE_TABLE + _CREATE_INDEX)
            await db.commit()
        self._initialized = True
        logger.info(f"Audit DB initialized: {self._db_path}")

    async def log(
        self,
        *,
        agent_id: str,
        agent_name: str,
        method: str,
        path: str,
        decision: str,
        deny_reason: str | None = None,
        status_code: int | None = None,
        latency_ms: float = 0,
        request_id: str,
    ) -> None:
        await self._ensure_init()
        try:
            async with aiosqlite.connect(self._db_path) as db:
                await db.execute(
                    """INSERT INTO audit_logs
                       (agent_id, agent_name, method, path, decision, deny_reason, status_code, latency_ms, request_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (agent_id, agent_name, method, path, decision, deny_reason, status_code, latency_ms, request_id),
                )
                await db.commit()
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    async def query(
        self,
        *,
        agent_id: str | None = None,
        decision: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """Query audit logs with optional filters and pagination."""
        await self._ensure_init()

        where_clauses: list[str] = []
        params: list[str | int] = []

        if agent_id:
            where_clauses.append("agent_id = ?")
            params.append(agent_id)
        if decision:
            where_clauses.append("decision = ?")
            params.append(decision)

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row

            # Total count
            cursor = await db.execute(
                f"SELECT COUNT(*) as cnt FROM audit_logs {where_sql}", params
            )
            row = await cursor.fetchone()
            total: int = row["cnt"] if row else 0

            # Fetch page
            cursor = await db.execute(
                f"SELECT * FROM audit_logs {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            )
            rows = await cursor.fetchall()
            logs: list[dict[str, Any]] = [dict(r) for r in rows]

        return logs, total

    async def is_healthy(self) -> bool:
        try:
            await self._ensure_init()
            async with aiosqlite.connect(self._db_path) as db:
                cursor = await db.execute("SELECT 1")
                await cursor.fetchone()
            return True
        except Exception:
            return False
