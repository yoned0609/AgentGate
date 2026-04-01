"""Analytics engine — time-series, anomaly detection, and heatmap data from audit logs."""

from __future__ import annotations

from typing import Any

import aiosqlite


class AnalyticsEngine:
    """Provides analytics views over the audit log for observability.

    All queries are read-only against the existing audit_logs table.
    """

    def __init__(self, db_path: str = "audit.db") -> None:
        self._db_path = db_path

    async def time_series(
        self,
        *,
        interval: str = "hour",
        agent_id: str | None = None,
        provider: str | None = None,
        hours: int = 24,
    ) -> list[dict[str, Any]]:
        """Aggregate request counts by time bucket.

        Args:
            interval: "minute", "hour", or "day".
            hours: Look-back window in hours.

        Returns list of {bucket, total, allowed, denied, rate_limited}.
        """
        fmt = {
            "minute": "%Y-%m-%d %H:%M:00",
            "hour": "%Y-%m-%d %H:00:00",
            "day": "%Y-%m-%d",
        }.get(interval, "%Y-%m-%d %H:00:00")

        where, params = self._build_where(agent_id=agent_id, provider=provider)
        time_filter = f"timestamp >= datetime('now', '-{hours} hours')"
        where = f"{where} AND {time_filter}" if where else f"WHERE {time_filter}"

        sql = f"""
            SELECT
                strftime('{fmt}', timestamp) AS bucket,
                COUNT(*) AS total,
                SUM(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END) AS allowed,
                SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END) AS denied,
                SUM(CASE WHEN decision = 'rate_limited' THEN 1 ELSE 0 END) AS rate_limited,
                ROUND(AVG(latency_ms), 2) AS avg_latency_ms
            FROM audit_logs
            {where}
            GROUP BY bucket
            ORDER BY bucket
        """

        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(sql, params)
            rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def deny_trends(
        self,
        *,
        agent_id: str | None = None,
        provider: str | None = None,
        hours: int = 24,
    ) -> dict[str, Any]:
        """Analyze deny patterns: top reasons, deny rate over time, spikes."""
        where, params = self._build_where(agent_id=agent_id, provider=provider)
        time_filter = f"timestamp >= datetime('now', '-{hours} hours')"
        where = f"{where} AND {time_filter}" if where else f"WHERE {time_filter}"

        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row

            # Top deny reasons
            cursor = await db.execute(
                f"""SELECT deny_reason, COUNT(*) AS cnt
                    FROM audit_logs
                    {where} AND decision = 'deny'
                    GROUP BY deny_reason ORDER BY cnt DESC LIMIT 10""",
                params,
            )
            top_reasons = [dict(r) for r in await cursor.fetchall()]

            # Deny rate by hour
            cursor = await db.execute(
                f"""SELECT
                        strftime('%Y-%m-%d %H:00:00', timestamp) AS bucket,
                        ROUND(
                            CAST(SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END) AS REAL)
                            / MAX(COUNT(*), 1), 4
                        ) AS deny_rate,
                        COUNT(*) AS total
                    FROM audit_logs
                    {where}
                    GROUP BY bucket ORDER BY bucket""",
                params,
            )
            deny_rate_series = [dict(r) for r in await cursor.fetchall()]

        return {
            "top_deny_reasons": top_reasons,
            "deny_rate_series": deny_rate_series,
        }

    async def agent_heatmap(
        self,
        *,
        hours: int = 24,
    ) -> list[dict[str, Any]]:
        """Generate agent x provider activity heatmap data."""
        sql = f"""
            SELECT
                agent_name,
                provider,
                decision,
                COUNT(*) AS cnt
            FROM audit_logs
            WHERE timestamp >= datetime('now', '-{hours} hours')
            GROUP BY agent_name, provider, decision
            ORDER BY cnt DESC
        """

        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(sql)
            rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def anomaly_detection(
        self,
        *,
        window_minutes: int = 10,
        threshold_multiplier: float = 3.0,
    ) -> list[dict[str, Any]]:
        """Detect anomalous traffic spikes per agent.

        Compares the last `window_minutes` to the baseline average.
        Flags agents whose recent request count exceeds baseline * threshold_multiplier.
        """
        sql = f"""
            WITH recent AS (
                SELECT agent_id, agent_name, COUNT(*) AS recent_count
                FROM audit_logs
                WHERE timestamp >= datetime('now', '-{window_minutes} minutes')
                GROUP BY agent_id
            ),
            baseline AS (
                SELECT agent_id,
                       COUNT(*) * 1.0 / MAX(
                           (julianday('now') - julianday(MIN(timestamp))) * 24 * 60 / {window_minutes},
                           1
                       ) AS avg_count_per_window
                FROM audit_logs
                WHERE timestamp >= datetime('now', '-24 hours')
                GROUP BY agent_id
            )
            SELECT
                r.agent_id,
                r.agent_name,
                r.recent_count,
                ROUND(b.avg_count_per_window, 1) AS baseline_avg,
                ROUND(r.recent_count * 1.0 / MAX(b.avg_count_per_window, 1), 2) AS spike_ratio
            FROM recent r
            JOIN baseline b ON r.agent_id = b.agent_id
            WHERE r.recent_count > b.avg_count_per_window * {threshold_multiplier}
            ORDER BY spike_ratio DESC
        """

        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(sql)
            rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def latency_percentiles(
        self,
        *,
        agent_id: str | None = None,
        provider: str | None = None,
        hours: int = 24,
    ) -> dict[str, Any]:
        """Calculate latency percentiles (p50, p90, p95, p99)."""
        where, params = self._build_where(agent_id=agent_id, provider=provider)
        time_filter = f"timestamp >= datetime('now', '-{hours} hours')"
        where = f"{where} AND {time_filter}" if where else f"WHERE {time_filter}"

        sql = f"""
            SELECT latency_ms FROM audit_logs
            {where}
            ORDER BY latency_ms
        """

        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(sql, params)
            rows = await cursor.fetchall()

        latencies = [r["latency_ms"] for r in rows]
        if not latencies:
            return {"count": 0, "p50": 0, "p90": 0, "p95": 0, "p99": 0}

        n = len(latencies)
        return {
            "count": n,
            "p50": round(latencies[int(n * 0.50)], 2),
            "p90": round(latencies[int(n * 0.90)], 2),
            "p95": round(latencies[int(n * 0.95)], 2),
            "p99": round(latencies[min(int(n * 0.99), n - 1)], 2),
            "max": round(latencies[-1], 2),
        }

    async def intent_distribution(
        self,
        *,
        provider: str | None = None,
        hours: int = 24,
    ) -> list[dict[str, Any]]:
        """Intent type distribution grouped by decision."""
        where, params = self._build_where(provider=provider)
        time_filter = f"timestamp >= datetime('now', '-{hours} hours')"
        where = f"{where} AND {time_filter}" if where else f"WHERE {time_filter}"

        sql = f"""
            SELECT intent, decision, COUNT(*) AS cnt
            FROM audit_logs
            {where}
            GROUP BY intent, decision
            ORDER BY cnt DESC
        """

        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(sql, params)
            rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    def _build_where(
        *,
        agent_id: str | None = None,
        provider: str | None = None,
    ) -> tuple[str, list[str]]:
        clauses: list[str] = []
        params: list[str] = []
        if agent_id:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if provider:
            clauses.append("provider = ?")
            params.append(provider)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params
