"""Cross-engagement persistent knowledge base.

Uses a separate SQLite database (clinkz_knowledge.db) that persists across
engagements. Stores playbook entries (tiered techniques), technique results,
technology relations, and past engagement summaries.

The KB grows with every pentest — what worked on Apache 2.4 last month
informs today's test against a similar stack.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import aiosqlite

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema DDL
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS playbook_entries (
    id INTEGER PRIMARY KEY,
    tier INTEGER NOT NULL CHECK(tier IN (1, 2, 3)),
    technology_pattern TEXT,
    technique_name TEXT NOT NULL,
    technique_description TEXT,
    steps TEXT,
    source_url TEXT,
    source_type TEXT,
    cve_id TEXT,
    severity TEXT,
    applicable_vuln_classes TEXT,
    times_tried INTEGER DEFAULT 0,
    times_succeeded INTEGER DEFAULT 0,
    success_rate REAL DEFAULT 0.0,
    last_used_date TEXT,
    created_from_engagement TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(technique_name, technology_pattern)
);

CREATE TABLE IF NOT EXISTS past_engagements (
    id INTEGER PRIMARY KEY,
    engagement_id TEXT UNIQUE NOT NULL,
    target_description TEXT,
    technologies TEXT,
    findings_count INTEGER DEFAULT 0,
    findings_summary TEXT,
    date TEXT,
    duration_minutes INTEGER
);

CREATE TABLE IF NOT EXISTS technique_results (
    id INTEGER PRIMARY KEY,
    playbook_entry_id INTEGER REFERENCES playbook_entries(id),
    engagement_id TEXT NOT NULL,
    technology_actual TEXT,
    success INTEGER NOT NULL,
    finding_id TEXT,
    response_summary TEXT,
    adaptation_notes TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS technology_relations (
    id INTEGER PRIMARY KEY,
    tech_a TEXT NOT NULL,
    tech_b TEXT NOT NULL,
    relation_type TEXT,
    similarity_score REAL CHECK(similarity_score BETWEEN 0 AND 1),
    notes TEXT,
    UNIQUE(tech_a, tech_b, relation_type)
);
"""


class PersistentKnowledgeBase:
    """Cross-engagement knowledge base that grows with every pentest.

    Uses a separate SQLite DB (clinkz_knowledge.db) that persists across
    engagements. Must be created via the async ``create()`` classmethod
    since ``__init__`` cannot be async.

    Usage::

        kb = await PersistentKnowledgeBase.create("clinkz_knowledge.db")
        entries = await kb.get_playbook_for_technology("Apache 2.4.51")
        await kb.close()
    """

    def __init__(self, db: aiosqlite.Connection, db_path: str) -> None:
        self._db = db
        self._db_path = db_path

    @classmethod
    async def create(cls, db_path: str = "clinkz_knowledge.db") -> PersistentKnowledgeBase:
        """Create and initialise the knowledge base.

        Args:
            db_path: Path to the SQLite database file.

        Returns:
            An initialised PersistentKnowledgeBase instance.
        """
        db = await aiosqlite.connect(db_path)
        db.row_factory = aiosqlite.Row
        instance = cls(db, db_path)
        await instance._init_db()
        logger.info("PersistentKB: opened %s", db_path)
        return instance

    async def _init_db(self) -> None:
        """Create tables if they don't exist."""
        await self._db.executescript(_SCHEMA)
        await self._db.commit()

    # ------------------------------------------------------------------
    # Playbook entries
    # ------------------------------------------------------------------

    async def add_playbook_entry(
        self,
        tier: int,
        technique_name: str,
        technology_pattern: str | None = None,
        technique_description: str | None = None,
        steps: list[str] | None = None,
        source_url: str | None = None,
        source_type: str | None = None,
        cve_id: str | None = None,
        severity: str | None = None,
        applicable_vuln_classes: list[str] | None = None,
        created_from_engagement: str | None = None,
    ) -> int:
        """Add a playbook entry. Returns the row id.

        Args:
            tier: 1 (universal), 2 (tech-matched), or 3 (experimental).
            technique_name: Short name for the technique.
            technology_pattern: Regex pattern to match technologies.
            technique_description: Human-readable description.
            steps: Ordered list of step strings.
            source_url: URL where the technique was found.
            source_type: "manual", "research_agent", "cve_db", "writeup".
            cve_id: Associated CVE identifier.
            severity: "critical", "high", "medium", "low", "info".
            applicable_vuln_classes: e.g. ["sqli", "xss"].
            created_from_engagement: Engagement ID that produced this entry.

        Returns:
            The row id of the inserted entry.
        """
        cursor = await self._db.execute(
            """INSERT INTO playbook_entries
               (tier, technology_pattern, technique_name, technique_description,
                steps, source_url, source_type, cve_id, severity,
                applicable_vuln_classes, created_from_engagement)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                tier,
                technology_pattern,
                technique_name,
                technique_description,
                json.dumps(steps) if steps else None,
                source_url,
                source_type,
                cve_id,
                severity,
                json.dumps(applicable_vuln_classes) if applicable_vuln_classes else None,
                created_from_engagement,
            ),
        )
        await self._db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    async def get_playbook_for_technology(self, technology: str) -> list[dict[str, Any]]:
        """Return playbook entries matching a technology string.

        Matches using ``re.search(pattern, technology, re.IGNORECASE)`` on
        each entry's ``technology_pattern``. Results sorted by tier ASC,
        success_rate DESC.

        Args:
            technology: Technology string to match (e.g. "Apache 2.4.51").

        Returns:
            List of matching playbook entry dicts.
        """
        cursor = await self._db.execute(
            "SELECT * FROM playbook_entries ORDER BY tier ASC, success_rate DESC"
        )
        rows = await cursor.fetchall()
        results = []
        for row in rows:
            pattern = row["technology_pattern"]
            if pattern and re.search(pattern, technology, re.IGNORECASE):
                results.append(self._row_to_dict(row))
        return results

    async def get_tier1_tests(self) -> list[dict[str, Any]]:
        """Return all Tier 1 (universal) playbook entries."""
        cursor = await self._db.execute(
            "SELECT * FROM playbook_entries WHERE tier = 1 ORDER BY success_rate DESC"
        )
        return [self._row_to_dict(row) for row in await cursor.fetchall()]

    async def get_tier2_tests(self, technology: str) -> list[dict[str, Any]]:
        """Return Tier 2 entries matching a technology."""
        cursor = await self._db.execute(
            "SELECT * FROM playbook_entries WHERE tier = 2 ORDER BY success_rate DESC"
        )
        rows = await cursor.fetchall()
        return [
            self._row_to_dict(row)
            for row in rows
            if row["technology_pattern"]
            and re.search(row["technology_pattern"], technology, re.IGNORECASE)
        ]

    async def get_tier3_tests(self, technology: str) -> list[dict[str, Any]]:
        """Return Tier 3 entries matching a technology."""
        cursor = await self._db.execute(
            "SELECT * FROM playbook_entries WHERE tier = 3 ORDER BY success_rate DESC"
        )
        rows = await cursor.fetchall()
        return [
            self._row_to_dict(row)
            for row in rows
            if row["technology_pattern"]
            and re.search(row["technology_pattern"], technology, re.IGNORECASE)
        ]

    # ------------------------------------------------------------------
    # Technique results
    # ------------------------------------------------------------------

    async def record_technique_result(
        self,
        entry_id: int,
        engagement_id: str,
        success: bool,
        finding_id: str | None = None,
        response_summary: str | None = None,
        adaptation_notes: str | None = None,
        technology_actual: str | None = None,
    ) -> None:
        """Record the result of running a technique.

        Also increments ``times_tried`` (and ``times_succeeded`` if success)
        on the corresponding playbook entry.

        Args:
            entry_id: Playbook entry id.
            engagement_id: Current engagement id.
            success: Whether the technique succeeded.
            finding_id: ID of the finding produced (if any).
            response_summary: Brief summary of the response.
            adaptation_notes: Notes on adaptations made.
            technology_actual: Actual technology encountered.
        """
        await self._db.execute(
            """INSERT INTO technique_results
               (playbook_entry_id, engagement_id, technology_actual, success,
                finding_id, response_summary, adaptation_notes)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                entry_id,
                engagement_id,
                technology_actual,
                1 if success else 0,
                finding_id,
                response_summary,
                adaptation_notes,
            ),
        )
        # Increment counters on playbook entry
        if success:
            await self._db.execute(
                """UPDATE playbook_entries
                   SET times_tried = times_tried + 1,
                       times_succeeded = times_succeeded + 1,
                       last_used_date = datetime('now'),
                       updated_at = datetime('now')
                   WHERE id = ?""",
                (entry_id,),
            )
        else:
            await self._db.execute(
                """UPDATE playbook_entries
                   SET times_tried = times_tried + 1,
                       last_used_date = datetime('now'),
                       updated_at = datetime('now')
                   WHERE id = ?""",
                (entry_id,),
            )
        await self._db.commit()

    async def update_success_rates(self) -> None:
        """Recalculate success_rate for all entries from technique_results."""
        await self._db.execute(
            """UPDATE playbook_entries
               SET success_rate = COALESCE(
                   (SELECT CAST(SUM(success) AS REAL) / COUNT(*)
                    FROM technique_results
                    WHERE technique_results.playbook_entry_id = playbook_entries.id),
                   0.0
               ),
               updated_at = datetime('now')"""
        )
        await self._db.commit()

    # ------------------------------------------------------------------
    # Technology relations
    # ------------------------------------------------------------------

    async def get_related_technologies(self, technology: str) -> list[dict[str, Any]]:
        """Find technologies related to the given one.

        Args:
            technology: Technology name to search for.

        Returns:
            List of relation dicts with tech_a, tech_b, relation_type, etc.
        """
        cursor = await self._db.execute(
            """SELECT * FROM technology_relations
               WHERE LOWER(tech_a) = LOWER(?) OR LOWER(tech_b) = LOWER(?)
               ORDER BY similarity_score DESC""",
            (technology, technology),
        )
        return [self._row_to_dict(row) for row in await cursor.fetchall()]

    async def add_technology_relation(
        self,
        tech_a: str,
        tech_b: str,
        relation_type: str,
        similarity_score: float,
        notes: str | None = None,
    ) -> None:
        """Add a technology relation.

        Args:
            tech_a: First technology.
            tech_b: Second technology.
            relation_type: "similar_stack", "commonly_paired", or "successor".
            similarity_score: 0.0 to 1.0.
            notes: Optional notes.
        """
        await self._db.execute(
            """INSERT OR IGNORE INTO technology_relations
               (tech_a, tech_b, relation_type, similarity_score, notes)
               VALUES (?, ?, ?, ?, ?)""",
            (tech_a, tech_b, relation_type, similarity_score, notes),
        )
        await self._db.commit()

    # ------------------------------------------------------------------
    # Engagements
    # ------------------------------------------------------------------

    async def record_engagement(
        self,
        engagement_id: str,
        target_description: str,
        technologies: list[str],
        findings_count: int,
        findings_summary: list[dict[str, str]],
        duration_minutes: int | None = None,
    ) -> None:
        """Record a completed engagement summary.

        Args:
            engagement_id: Unique engagement identifier.
            target_description: Human-readable target description.
            technologies: List of technology strings found.
            findings_count: Total number of findings.
            findings_summary: List of {title, severity, category} dicts.
            duration_minutes: How long the engagement took.
        """
        await self._db.execute(
            """INSERT OR REPLACE INTO past_engagements
               (engagement_id, target_description, technologies, findings_count,
                findings_summary, date, duration_minutes)
               VALUES (?, ?, ?, ?, ?, datetime('now'), ?)""",
            (
                engagement_id,
                target_description,
                json.dumps(technologies),
                findings_count,
                json.dumps(findings_summary),
                duration_minutes,
            ),
        )
        await self._db.commit()

    # ------------------------------------------------------------------
    # Cross-engagement queries
    # ------------------------------------------------------------------

    async def get_past_results_for_technology(self, technology: str) -> list[dict[str, Any]]:
        """Get technique results for entries matching a technology.

        Joins technique_results with playbook_entries where the entry's
        technology_pattern matches the given technology string.

        Args:
            technology: Technology to match against playbook patterns.

        Returns:
            List of joined result dicts.
        """
        cursor = await self._db.execute(
            """SELECT tr.*, pe.technique_name, pe.tier, pe.technology_pattern,
                      pe.severity, pe.applicable_vuln_classes
               FROM technique_results tr
               JOIN playbook_entries pe ON tr.playbook_entry_id = pe.id
               ORDER BY tr.created_at DESC"""
        )
        rows = await cursor.fetchall()
        results = []
        for row in rows:
            pattern = row["technology_pattern"]
            if pattern and re.search(pattern, technology, re.IGNORECASE):
                results.append(self._row_to_dict(row))
        return results

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the database connection."""
        await self._db.close()
        logger.info("PersistentKB: closed %s", self._db_path)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: aiosqlite.Row) -> dict[str, Any]:
        """Convert an aiosqlite Row to a plain dict."""
        return dict(row)
