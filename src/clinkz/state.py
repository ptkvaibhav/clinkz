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

CREATE TABLE IF NOT EXISTS agent_messages (
    id                TEXT PRIMARY KEY,
    engagement_id     TEXT NOT NULL REFERENCES engagements(id),
    from_agent        TEXT NOT NULL,
    to_agent          TEXT NOT NULL,
    message_type      TEXT NOT NULL,
    content_json      TEXT NOT NULL,
    parent_message_id TEXT,
    timestamp         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id),
    agent           TEXT NOT NULL,
    cookies_json    TEXT NOT NULL DEFAULT '{}',
    cookie_jar_path TEXT NOT NULL DEFAULT '',
    metadata_json   TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoints (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id),
    url             TEXT NOT NULL,
    method          TEXT NOT NULL DEFAULT 'GET',
    parameters      TEXT NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'discovered',
    discovered_by   TEXT NOT NULL DEFAULT '',
    tested_by       TEXT,
    service_type    TEXT NOT NULL DEFAULT 'http',
    port            INTEGER,
    notes           TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_endpoints_url_method
    ON endpoints(engagement_id, url, method);

CREATE TABLE IF NOT EXISTS runbook (
    id                    TEXT PRIMARY KEY,
    engagement_id         TEXT NOT NULL REFERENCES engagements(id),
    technology            TEXT NOT NULL,
    technique_name        TEXT NOT NULL,
    technique_description TEXT NOT NULL DEFAULT '',
    source_url            TEXT NOT NULL DEFAULT '',
    source_type           TEXT NOT NULL DEFAULT 'other',
    steps                 TEXT NOT NULL DEFAULT '[]',
    applicable_to         TEXT NOT NULL DEFAULT '[]',
    cve_id                TEXT,
    severity              TEXT NOT NULL DEFAULT 'info',
    created_at            TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_runbook_tech_technique
    ON runbook(engagement_id, technology, technique_name);
"""

# Migrations for existing tables — ALTER TABLE is idempotent via try/except
_MIGRATIONS = [
    "ALTER TABLE targets ADD COLUMN service_type TEXT NOT NULL DEFAULT 'other'",
    "ALTER TABLE findings ADD COLUMN source_technique TEXT",
]


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
        # Enable WAL mode for safe concurrent reads + writes from multiple agents
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.executescript(_SCHEMA_SQL)
        await self._db.commit()
        # Run ALTER TABLE migrations (idempotent — duplicates are ignored)
        for migration in _MIGRATIONS:
            try:
                await self._db.execute(migration)
            except Exception:  # noqa: BLE001 — column already exists
                pass
        await self._db.commit()
        logger.info("State store connected (WAL mode): %s", self.db_path)

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

    async def upsert_target(
        self,
        engagement_id: str,
        host_data: dict[str, Any],
        deduplicate: bool = True,
    ) -> str:
        """Insert or replace a host target. Returns the target ID.

        When *deduplicate* is True (the default), an existing target with the
        same ``ip`` value within the same engagement is returned instead of
        creating a duplicate row.

        Args:
            engagement_id: Parent engagement UUID.
            host_data: Serialized Host model dict. Must include 'id' if updating.
            deduplicate: Check for existing target with same ip before inserting.

        Returns:
            Target UUID (existing or newly created).
        """
        # --- Deduplication check ---
        if deduplicate and "ip" in host_data:
            existing = await self._find_existing_target(engagement_id, host_data["ip"])
            if existing is not None:
                logger.debug(
                    "Dedup: target '%s' already exists as %s — skipping insert",
                    host_data["ip"],
                    existing,
                )
                return existing

        target_id = host_data.get("id") or self._new_id()
        host_data = {**host_data, "id": target_id}
        await self._conn.execute(
            "INSERT OR REPLACE INTO targets (id, engagement_id, host_json, created_at) "
            "VALUES (?, ?, ?, ?)",
            (target_id, engagement_id, json.dumps(host_data), self._now()),
        )
        await self._conn.commit()
        return target_id

    async def _find_existing_target(self, engagement_id: str, ip: str) -> str | None:
        """Return the ID of an existing target matching *ip*, or None.

        Performs a JSON extraction on the stored ``host_json`` to compare the
        ``ip`` field, which doubles as the URL/path key for scan endpoints.

        Args:
            engagement_id: Engagement UUID.
            ip: The ip/url/path value to match against.

        Returns:
            Target UUID if found, else None.
        """
        async with self._conn.execute(
            "SELECT id FROM targets "
            "WHERE engagement_id = ? AND json_extract(host_json, '$.ip') = ?",
            (engagement_id, ip),
        ) as cursor:
            row = await cursor.fetchone()
        return row["id"] if row else None

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

    async def get_actions(self, engagement_id: str) -> list[dict[str, Any]]:
        """Return all actions logged for an engagement.

        Args:
            engagement_id: Engagement UUID.

        Returns:
            List of action dicts (all columns from the actions table).
        """
        async with self._conn.execute(
            "SELECT * FROM actions WHERE engagement_id=? ORDER BY created_at",
            (engagement_id,),
        ) as cursor:
            rows = await cursor.fetchall()
        return [dict(row) for row in rows]

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

    # ------------------------------------------------------------------
    # Agent messages (inter-agent communication audit trail)
    # ------------------------------------------------------------------

    async def save_message(self, message: AgentMessage) -> None:  # noqa: F821
        """Persist an AgentMessage to the audit trail.

        Accepts any object that has the AgentMessage fields; typed as a
        forward reference to avoid a circular import (comms → state).

        Args:
            message: AgentMessage to persist.
        """
        await self._conn.execute(
            "INSERT OR IGNORE INTO agent_messages "
            "(id, engagement_id, from_agent, to_agent, message_type, "
            "content_json, parent_message_id, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                message.id,
                message.engagement_id,
                message.from_agent,
                message.to_agent,
                str(message.message_type),
                json.dumps(message.content),
                message.parent_message_id,
                message.timestamp.isoformat(),
            ),
        )
        await self._conn.commit()

    # ------------------------------------------------------------------
    # Sessions (authenticated session handoff between agents)
    # ------------------------------------------------------------------

    async def save_session(
        self,
        engagement_id: str,
        agent: str,
        cookies: dict[str, str],
        cookie_jar_path: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Persist an authenticated session for cross-agent handoff.

        When an agent (e.g., Scan) successfully authenticates, it stores
        the session cookies here so later agents (e.g., Exploit) can reuse
        the authenticated state without re-authenticating.

        Args:
            engagement_id: Parent engagement UUID.
            agent: Agent name that created the session (e.g., "scan").
            cookies: Session cookies as key-value pairs.
            cookie_jar_path: Path to the Netscape cookie jar file on disk.
            metadata: Arbitrary extra data (e.g., login URL, technology).

        Returns:
            Session UUID.
        """
        sid = self._new_id()
        now = self._now()
        await self._conn.execute(
            "INSERT INTO sessions "
            "(id, engagement_id, agent, cookies_json, cookie_jar_path, "
            "metadata_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                sid,
                engagement_id,
                agent,
                json.dumps(cookies),
                cookie_jar_path,
                json.dumps(metadata or {}),
                now,
                now,
            ),
        )
        await self._conn.commit()
        logger.debug("Saved session %s from agent '%s'", sid, agent)
        return sid

    async def get_sessions(self, engagement_id: str) -> list[dict[str, Any]]:
        """Return all saved sessions for an engagement.

        Args:
            engagement_id: Engagement UUID.

        Returns:
            List of session dicts with deserialized cookies and metadata.
        """
        async with self._conn.execute(
            "SELECT * FROM sessions WHERE engagement_id=? ORDER BY created_at",
            (engagement_id,),
        ) as cursor:
            rows = await cursor.fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            results.append(
                {
                    "id": row["id"],
                    "engagement_id": row["engagement_id"],
                    "agent": row["agent"],
                    "cookies": json.loads(row["cookies_json"]),
                    "cookie_jar_path": row["cookie_jar_path"],
                    "metadata": json.loads(row["metadata_json"]),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                }
            )
        return results

    async def get_messages(
        self,
        engagement_id: str,
        agent_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return persisted agent messages for an engagement.

        Args:
            engagement_id: Engagement UUID.
            agent_name: If provided, return only messages TO or FROM this agent.

        Returns:
            List of message dicts ordered by timestamp.
        """
        if agent_name:
            query = (
                "SELECT * FROM agent_messages "
                "WHERE engagement_id=? AND (from_agent=? OR to_agent=?) "
                "ORDER BY timestamp"
            )
            params: tuple[Any, ...] = (engagement_id, agent_name, agent_name)
        else:
            query = "SELECT * FROM agent_messages WHERE engagement_id=? ORDER BY timestamp"
            params = (engagement_id,)

        async with self._conn.execute(query, params) as cursor:
            rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Endpoints (attack surface tracking for concurrent agents)
    # ------------------------------------------------------------------

    async def add_endpoint(
        self,
        engagement_id: str,
        url: str,
        method: str = "GET",
        parameters: dict[str, Any] | None = None,
        service_type: str = "http",
        discovered_by: str = "",
        port: int | None = None,
        notes: str = "",
    ) -> str:
        """Add a discovered endpoint, deduplicating on url+method.

        If an endpoint with the same url and method already exists within the
        engagement, the existing record is updated with any new parameters and
        notes instead of creating a duplicate.

        Args:
            engagement_id: Parent engagement UUID.
            url: Full URL or service address.
            method: HTTP method or protocol action (default GET).
            parameters: Discovered parameters as key-value pairs.
            service_type: One of http/ftp/ssh/smb/database/other.
            discovered_by: Agent name that found this endpoint.
            port: Port number (optional).
            notes: Free-text notes.

        Returns:
            Endpoint UUID (existing or newly created).
        """
        eid = self._new_id()
        now = self._now()
        params_json = json.dumps(parameters or {})
        try:
            await self._conn.execute(
                "INSERT INTO endpoints "
                "(id, engagement_id, url, method, parameters, status, "
                "discovered_by, service_type, port, notes, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, 'discovered', ?, ?, ?, ?, ?, ?)",
                (
                    eid,
                    engagement_id,
                    url,
                    method,
                    params_json,
                    discovered_by,
                    service_type,
                    port,
                    notes,
                    now,
                    now,
                ),
            )
            await self._conn.commit()
            return eid
        except Exception:  # noqa: BLE001 — UNIQUE constraint = dedup
            # Update existing record with merged info
            await self._conn.execute(
                "UPDATE endpoints SET parameters=?, notes=?, updated_at=? "
                "WHERE engagement_id=? AND url=? AND method=?",
                (params_json, notes, now, engagement_id, url, method),
            )
            await self._conn.commit()
            # Return existing ID
            async with self._conn.execute(
                "SELECT id FROM endpoints WHERE engagement_id=? AND url=? AND method=?",
                (engagement_id, url, method),
            ) as cursor:
                row = await cursor.fetchone()
            return row["id"]  # type: ignore[index]

    async def get_endpoints(
        self,
        engagement_id: str,
        status: str | None = None,
        service_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return endpoints for an engagement with optional filters.

        Args:
            engagement_id: Engagement UUID.
            status: Filter by status (discovered/testing/tested/skipped).
            service_type: Filter by service type (http/ftp/ssh/etc.).

        Returns:
            List of endpoint dicts with deserialized parameters.
        """
        query = "SELECT * FROM endpoints WHERE engagement_id=?"
        params: list[Any] = [engagement_id]
        if status is not None:
            query += " AND status=?"
            params.append(status)
        if service_type is not None:
            query += " AND service_type=?"
            params.append(service_type)
        query += " ORDER BY created_at"
        async with self._conn.execute(query, params) as cursor:
            rows = await cursor.fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            d = dict(row)
            d["parameters"] = json.loads(d["parameters"])
            results.append(d)
        return results

    async def get_new_endpoints(self, engagement_id: str) -> list[dict[str, Any]]:
        """Return only endpoints with status='discovered' (not yet tested).

        Args:
            engagement_id: Engagement UUID.

        Returns:
            List of endpoint dicts.
        """
        return await self.get_endpoints(engagement_id, status="discovered")

    async def update_endpoint_status(
        self,
        endpoint_id: str,
        status: str,
        tested_by: str | None = None,
    ) -> None:
        """Update the status of an endpoint.

        Args:
            endpoint_id: Endpoint UUID.
            status: New status (discovered/testing/tested/skipped).
            tested_by: Agent name that tested this endpoint.
        """
        await self._conn.execute(
            "UPDATE endpoints SET status=?, tested_by=?, updated_at=? WHERE id=?",
            (status, tested_by, self._now(), endpoint_id),
        )
        await self._conn.commit()

    # ------------------------------------------------------------------
    # Runbook (exploit technique knowledge base per engagement)
    # ------------------------------------------------------------------

    async def add_runbook_entry(
        self,
        engagement_id: str,
        technology: str,
        technique_name: str,
        technique_description: str = "",
        source_url: str = "",
        source_type: str = "other",
        steps: list[str] | None = None,
        applicable_to: list[str] | None = None,
        cve_id: str | None = None,
        severity: str = "info",
    ) -> str | None:
        """Add a technique to the engagement runbook. Deduplicates on technology+technique_name.

        Args:
            engagement_id: Parent engagement UUID.
            technology: Target technology (e.g., "nginx 1.24", "WordPress 6.x").
            technique_name: Short name for the technique.
            technique_description: Detailed description.
            source_url: URL where the technique was found.
            source_type: One of cve/hackerone/bugcrowd/medium/reddit/exploit_db/other.
            steps: Ordered list of exploitation steps.
            applicable_to: List of vulnerability classes this applies to.
            cve_id: CVE identifier if applicable.
            severity: Severity level (info/low/medium/high/critical).

        Returns:
            Runbook entry UUID, or None if a duplicate was skipped.
        """
        rid = self._new_id()
        now = self._now()
        try:
            await self._conn.execute(
                "INSERT INTO runbook "
                "(id, engagement_id, technology, technique_name, "
                "technique_description, source_url, source_type, steps, "
                "applicable_to, cve_id, severity, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    rid,
                    engagement_id,
                    technology,
                    technique_name,
                    technique_description,
                    source_url,
                    source_type,
                    json.dumps(steps or []),
                    json.dumps(applicable_to or []),
                    cve_id,
                    severity,
                    now,
                ),
            )
            await self._conn.commit()
            return rid
        except Exception:  # noqa: BLE001 — UNIQUE constraint = dedup skip
            logger.debug(
                "Runbook dedup: %s / %s already exists — skipping",
                technology,
                technique_name,
            )
            return None

    async def get_runbook_for_technology(
        self,
        engagement_id: str,
        technology: str,
    ) -> list[dict[str, Any]]:
        """Return all runbook entries for a specific technology.

        Args:
            engagement_id: Engagement UUID.
            technology: Technology string to match.

        Returns:
            List of runbook entry dicts with deserialized JSON fields.
        """
        async with self._conn.execute(
            "SELECT * FROM runbook WHERE engagement_id=? AND technology=? ORDER BY created_at",
            (engagement_id, technology),
        ) as cursor:
            rows = await cursor.fetchall()
        return [self._deserialize_runbook_row(row) for row in rows]

    async def get_all_runbook_entries(
        self,
        engagement_id: str,
    ) -> list[dict[str, Any]]:
        """Return all runbook entries for an engagement.

        Args:
            engagement_id: Engagement UUID.

        Returns:
            List of runbook entry dicts.
        """
        async with self._conn.execute(
            "SELECT * FROM runbook WHERE engagement_id=? ORDER BY created_at",
            (engagement_id,),
        ) as cursor:
            rows = await cursor.fetchall()
        return [self._deserialize_runbook_row(row) for row in rows]

    @staticmethod
    def _deserialize_runbook_row(row: Any) -> dict[str, Any]:
        """Convert a runbook DB row to a dict with deserialized JSON fields."""
        d = dict(row)
        d["steps"] = json.loads(d["steps"])
        d["applicable_to"] = json.loads(d["applicable_to"])
        return d
