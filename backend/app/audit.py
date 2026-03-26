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
    provider TEXT NOT NULL DEFAULT '',
    decision TEXT NOT NULL,
    deny_reason TEXT,
    intent TEXT DEFAULT '',
    intent_confidence REAL DEFAULT 0,
    status_code INTEGER,
    latency_ms REAL NOT NULL DEFAULT 0,
    request_id TEXT NOT NULL
);
"""

_CREATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_logs(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_provider ON audit_logs(provider);
"""

# Migrations for existing databases (add new columns if missing)
_MIGRATIONS = [
    "ALTER TABLE audit_logs ADD COLUMN provider TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE audit_logs ADD COLUMN intent TEXT DEFAULT ''",
    "ALTER TABLE audit_logs ADD COLUMN intent_confidence REAL DEFAULT 0",
]


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
            # Run migrations (ignore errors for columns that already exist)
            for migration in _MIGRATIONS:
                try:
                    await db.execute(migration)
                except Exception:
                    pass  # Column already exists
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
        provider: str = "",
        decision: str,
        deny_reason: str | None = None,
        intent: str = "",
        intent_confidence: float = 0,
        status_code: int | None = None,
        latency_ms: float = 0,
        request_id: str,
    ) -> None:
        await self._ensure_init()
        try:
            async with aiosqlite.connect(self._db_path) as db:
                await db.execute(
                    """INSERT INTO audit_logs
                       (agent_id, agent_name, method, path, provider, decision,
                        deny_reason, intent, intent_confidence, status_code, latency_ms, request_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        agent_id,
                        agent_name,
                        method,
                        path,
                        provider,
                        decision,
                        deny_reason,
                        intent,
                        intent_confidence,
                        status_code,
                        latency_ms,
                        request_id,
                    ),
                )
                await db.commit()
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    async def query(
        self,
        *,
        agent_id: str | None = None,
        decision: str | None = None,
        provider: str | None = None,
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
        if provider:
            where_clauses.append("provider = ?")
            params.append(provider)

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row

            cursor = await db.execute(
                f"SELECT COUNT(*) as cnt FROM audit_logs {where_sql}", params
            )
            row = await cursor.fetchone()
            total: int = row["cnt"] if row else 0

            cursor = await db.execute(
                f"SELECT * FROM audit_logs {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            )
            rows = await cursor.fetchall()
            logs: list[dict[str, Any]] = [dict(r) for r in rows]

        return logs, total

    async def stats(
        self,
        *,
        agent_id: str | None = None,
        provider: str | None = None,
    ) -> dict[str, Any]:
        """Aggregate statistics: total counts, deny rate, per-provider breakdown."""
        await self._ensure_init()

        where_clauses: list[str] = []
        params: list[str] = []
        if agent_id:
            where_clauses.append("agent_id = ?")
            params.append(agent_id)
        if provider:
            where_clauses.append("provider = ?")
            params.append(provider)
        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row

            # Total counts by decision
            cursor = await db.execute(
                f"SELECT decision, COUNT(*) as cnt FROM audit_logs {where_sql} GROUP BY decision",
                params,
            )
            decision_counts: dict[str, int] = {}
            for row in await cursor.fetchall():
                decision_counts[row["decision"]] = row["cnt"]

            total = sum(decision_counts.values())
            deny_count = decision_counts.get("deny", 0) + decision_counts.get(
                "rate_limited", 0
            )

            # Per-provider breakdown
            cursor = await db.execute(
                f"SELECT provider, COUNT(*) as cnt FROM audit_logs {where_sql} GROUP BY provider",
                params,
            )
            by_provider: dict[str, int] = {}
            for row in await cursor.fetchall():
                by_provider[row["provider"] or "unknown"] = row["cnt"]

            # Average latency
            cursor = await db.execute(
                f"SELECT AVG(latency_ms) as avg_lat, MAX(latency_ms) as max_lat FROM audit_logs {where_sql}",
                params,
            )
            lat_row = await cursor.fetchone()
            avg_latency = round(lat_row["avg_lat"] or 0, 2)
            max_latency = round(lat_row["max_lat"] or 0, 2)

        return {
            "total_requests": total,
            "by_decision": decision_counts,
            "deny_rate": round(deny_count / total, 4) if total > 0 else 0.0,
            "by_provider": by_provider,
            "avg_latency_ms": avg_latency,
            "max_latency_ms": max_latency,
        }

    async def export(
        self,
        *,
        agent_id: str | None = None,
        decision: str | None = None,
        provider: str | None = None,
        limit: int = 10000,
    ) -> list[dict[str, Any]]:
        """Export audit logs as a flat list (for JSON/CSV download)."""
        await self._ensure_init()

        where_clauses: list[str] = []
        params: list[str | int] = []
        if agent_id:
            where_clauses.append("agent_id = ?")
            params.append(agent_id)
        if decision:
            where_clauses.append("decision = ?")
            params.append(decision)
        if provider:
            where_clauses.append("provider = ?")
            params.append(provider)
        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                f"SELECT * FROM audit_logs {where_sql} ORDER BY id DESC LIMIT ?",
                [*params, limit],
            )
            rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def purge(self, *, retention_days: int = 90) -> int:
        """Delete audit logs older than retention_days. Returns count deleted."""
        await self._ensure_init()
        async with aiosqlite.connect(self._db_path) as db:
            cursor = await db.execute(
                "DELETE FROM audit_logs WHERE timestamp < datetime('now', ?)",
                (f"-{retention_days} days",),
            )
            count = cursor.rowcount
            await db.commit()
        if count > 0:
            logger.info(f"Purged {count} audit logs older than {retention_days} days")
        return count

    async def is_healthy(self) -> bool:
        try:
            await self._ensure_init()
            async with aiosqlite.connect(self._db_path) as db:
                cursor = await db.execute("SELECT 1")
                await cursor.fetchone()
            return True
        except Exception:
            return False
