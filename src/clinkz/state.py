"""Engagement state store backed by SQLite (async via aiosqlite).

Tracks targets, findings, agent actions, and retry attempts for a
single penetration testing engagement. Designed to be upgraded to
PostgreSQL later with minimal interface changes.

Usage::

    async with StateStore("clinkz.db") as state:
        eid = await state.create_engagement("ACME Corp", scope.model_dump())
        await state.upsert_target(eid, host.model_dump())
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiosqlite

logger = logging.getLogger(__name__)

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS engagements (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    scope_json  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id),
    host_json       TEXT NOT NULL,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id),
    target_id       TEXT REFERENCES targets(id),
    finding_json    TEXT NOT NULL,
    validated       INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actions (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id),
    phase           TEXT NOT NULL,
    agent           TEXT NOT NULL,
    tool            TEXT,
    input_json      TEXT,
    output_json     TEXT,
    status          TEXT NOT NULL DEFAULT 'pending',
    created_at      TEXT NOT NULL,
    completed_at    TEXT
);

CREATE TABLE IF NOT EXISTS attempts (
    id              TEXT PRIMARY KEY,
    action_id       TEXT NOT NULL REFERENCES actions(id),
    attempt_number  INTEGER NOT NULL,
    error           TEXT,
    created_at      TEXT NOT NULL
);
"""


class StateStore:
    """Async SQLite-backed state store for a pentest engagement.

    Supports context-manager usage::

        async with StateStore(db_path) as store:
            eid = await store.create_engagement(...)
    """

    def __init__(self, db_path: Path | str = "clinkz.db") -> None:
        self.db_path = Path(db_path)
        self._db: aiosqlite.Connection | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open the database and create schema if needed."""
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(_SCHEMA_SQL)
        await self._db.commit()
        logger.info("State store connected: %s", self.db_path)

    async def close(self) -> None:
        """Close the database connection."""
        if self._db:
            await self._db.close()
            self._db = None

    async def __aenter__(self) -> StateStore:
        await self.connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def _conn(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError(
                "StateStore not connected. Call connect() or use as context manager."
            )
        return self._db

    def _now(self) -> str:
        return datetime.now(UTC).isoformat()

    def _new_id(self) -> str:
        return str(uuid.uuid4())

    # ------------------------------------------------------------------
    # Engagements
    # ------------------------------------------------------------------

    async def create_engagement(self, name: str, scope: dict[str, Any]) -> str:
        """Create a new engagement record and return its ID.

        Args:
            name: Human-readable engagement name (e.g., "ACME Corp Q1 2025").
            scope: Serialized EngagementScope dict.

        Returns:
            New engagement UUID.
        """
        eid = self._new_id()
        now = self._now()
        await self._conn.execute(
            "INSERT INTO engagements (id, name, scope_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (eid, name, json.dumps(scope), now, now),
        )
        await self._conn.commit()
        logger.info("Created engagement: %s (%s)", name, eid)
        return eid

    async def update_engagement_status(self, engagement_id: str, status: str) -> None:
        """Update the status of an engagement (e.g., 'completed', 'failed').

        Args:
            engagement_id: Engagement UUID.
            status: New status string.
        """
        await self._conn.execute(
            "UPDATE engagements SET status=?, updated_at=? WHERE id=?",
            (status, self._now(), engagement_id),
        )
        await self._conn.commit()

    # ------------------------------------------------------------------
    # Targets
    # ------------------------------------------------------------------

    async def upsert_target(self, engagement_id: str, host_data: dict[str, Any]) -> str:
        """Insert or replace a host target. Returns the target ID.

        Args:
            engagement_id: Parent engagement UUID.
            host_data: Serialized Host model dict. Must include 'id' if updating.

        Returns:
            Target UUID.
        """
        target_id = host_data.get("id") or self._new_id()
        host_data = {**host_data, "id": target_id}
        await self._conn.execute(
            "INSERT OR REPLACE INTO targets (id, engagement_id, host_json, created_at) "
            "VALUES (?, ?, ?, ?)",
            (target_id, engagement_id, json.dumps(host_data), self._now()),
        )
        await self._conn.commit()
        return target_id

    async def get_targets(self, engagement_id: str) -> list[dict[str, Any]]:
        """Return all targets for an engagement.

        Args:
            engagement_id: Engagement UUID.

        Returns:
            List of deserialized Host dicts.
        """
        async with self._conn.execute(
            "SELECT host_json FROM targets WHERE engagement_id=?", (engagement_id,)
        ) as cursor:
            rows = await cursor.fetchall()
        return [json.loads(row["host_json"]) for row in rows]

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    async def add_finding(
        self,
        engagement_id: str,
        finding_data: dict[str, Any],
        target_id: str | None = None,
    ) -> str:
        """Persist a new vulnerability finding.

        Args:
            engagement_id: Parent engagement UUID.
            finding_data: Serialized Finding model dict.
            target_id: Optional target UUID this finding belongs to.

        Returns:
            Finding UUID.
        """
        fid = finding_data.get("id") or self._new_id()
        finding_data = {**finding_data, "id": fid}
        await self._conn.execute(
            "INSERT INTO findings "
            "(id, engagement_id, target_id, finding_json, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (fid, engagement_id, target_id, json.dumps(finding_data), self._now()),
        )
        await self._conn.commit()
        return fid

    async def get_findings(
        self,
        engagement_id: str,
        validated_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Return findings for an engagement.

        Args:
            engagement_id: Engagement UUID.
            validated_only: If True, return only Critic-validated findings.

        Returns:
            List of deserialized Finding dicts.
        """
        query = "SELECT finding_json FROM findings WHERE engagement_id=?"
        params: list[Any] = [engagement_id]
        if validated_only:
            query += " AND validated=1"
        async with self._conn.execute(query, params) as cursor:
            rows = await cursor.fetchall()
        return [json.loads(row["finding_json"]) for row in rows]

    async def mark_finding_validated(self, finding_id: str) -> None:
        """Mark a finding as validated by the Critic Agent.

        Args:
            finding_id: Finding UUID.
        """
        await self._conn.execute("UPDATE findings SET validated=1 WHERE id=?", (finding_id,))
        await self._conn.commit()

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    async def log_action(
        self,
        engagement_id: str,
        phase: str,
        agent: str,
        tool: str | None = None,
        input_data: dict[str, Any] | None = None,
    ) -> str:
        """Log a new agent action (tool invocation or LLM call).

        Args:
            engagement_id: Engagement UUID.
            phase: Pentest phase name (e.g., "recon", "exploit").
            agent: Agent class name.
            tool: Tool name if this is a tool invocation.
            input_data: Input arguments passed to the tool.

        Returns:
            Action UUID.
        """
        aid = self._new_id()
        await self._conn.execute(
            "INSERT INTO actions "
            "(id, engagement_id, phase, agent, tool, input_json, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)",
            (aid, engagement_id, phase, agent, tool, json.dumps(input_data), self._now()),
        )
        await self._conn.commit()
        return aid

    async def complete_action(
        self,
        action_id: str,
        output_data: dict[str, Any] | None = None,
        status: str = "completed",
    ) -> None:
        """Mark an action as completed (or failed).

        Args:
            action_id: Action UUID.
            output_data: Tool output or LLM response.
            status: Final status — 'completed' or 'failed'.
        """
        await self._conn.execute(
            "UPDATE actions SET status=?, output_json=?, completed_at=? WHERE id=?",
            (status, json.dumps(output_data), self._now(), action_id),
        )
        await self._conn.commit()

    # ------------------------------------------------------------------
    # Attempts (retry tracking)
    # ------------------------------------------------------------------

    async def log_attempt(
        self,
        action_id: str,
        attempt_number: int,
        error: str | None = None,
    ) -> str:
        """Record one attempt at executing an action.

        Args:
            action_id: Parent action UUID.
            attempt_number: 1-based attempt counter.
            error: Error message if the attempt failed, else None.

        Returns:
            Attempt UUID.
        """
        attempt_id = self._new_id()
        await self._conn.execute(
            "INSERT INTO attempts (id, action_id, attempt_number, error, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (attempt_id, action_id, attempt_number, error, self._now()),
        )
        await self._conn.commit()
        return attempt_id
