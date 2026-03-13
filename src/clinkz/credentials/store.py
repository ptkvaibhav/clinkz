"""Credential Store — shared credential management across all agents.

Tracks discovered, default, and validated credentials for an engagement.
Backed by a 'credentials' table added to the SQLite state store.

Usage::

    async with StateStore("clinkz.db") as state:
        cred_store = CredentialStore(state)
        await cred_store.initialize()

        # Add a discovered credential
        await cred_store.add(eid, "admin", "password", technology="dvwa", source="default")

        # Check defaults for a technology
        defaults = cred_store.get_defaults_for_technology("dvwa")

        # Mark as valid after successful login
        await cred_store.mark_valid(cred_id)
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel

from clinkz.state import StateStore

logger = logging.getLogger(__name__)


class Credential(BaseModel):
    """A single credential pair."""

    id: str
    engagement_id: str
    username: str
    password: str
    technology: str = ""
    source: str = ""  # "default", "discovered", "bruteforce", "osint"
    url: str = ""  # URL where this credential works
    valid: bool | None = None  # None=untested, True=confirmed, False=invalid
    created_at: str = ""


# ---------------------------------------------------------------------------
# Default credentials for common technologies
# ---------------------------------------------------------------------------

_DEFAULT_CREDENTIALS: list[dict[str, str]] = [
    # DVWA
    {"username": "admin", "password": "password", "technology": "dvwa"},
    # Tomcat
    {"username": "tomcat", "password": "tomcat", "technology": "tomcat"},
    {"username": "admin", "password": "tomcat", "technology": "tomcat"},
    # WordPress
    {"username": "admin", "password": "admin", "technology": "wordpress"},
    # phpMyAdmin
    {"username": "root", "password": "", "technology": "phpmyadmin"},
    # Juice Shop
    {"username": "admin", "password": "admin123", "technology": "juice_shop"},
    # Generic common defaults
    {"username": "admin", "password": "admin", "technology": "generic"},
    {"username": "root", "password": "root", "technology": "generic"},
    {"username": "admin", "password": "password", "technology": "generic"},
    {"username": "test", "password": "test", "technology": "generic"},
]

_CREDENTIALS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS credentials (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id),
    username        TEXT NOT NULL,
    password        TEXT NOT NULL,
    technology      TEXT NOT NULL DEFAULT '',
    source          TEXT NOT NULL DEFAULT '',
    url             TEXT NOT NULL DEFAULT '',
    valid           INTEGER,  -- NULL=untested, 1=valid, 0=invalid
    created_at      TEXT NOT NULL
);
"""


class CredentialStore:
    """Manages credentials for a pentest engagement.

    Wraps the StateStore to provide credential-specific operations
    including default credential lookups and validity tracking.

    Args:
        state: Connected StateStore instance.
    """

    def __init__(self, state: StateStore) -> None:
        self._state = state

    async def initialize(self) -> None:
        """Create the credentials table if it doesn't exist."""
        await self._state._conn.executescript(_CREDENTIALS_TABLE_SQL)
        await self._state._conn.commit()
        logger.info("Credential store initialized")

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def add(
        self,
        engagement_id: str,
        username: str,
        password: str,
        technology: str = "",
        source: str = "",
        url: str = "",
    ) -> str:
        """Add a credential to the store.

        Args:
            engagement_id: Parent engagement UUID.
            username: Username or login identifier.
            password: Password or secret.
            technology: Technology this credential is for (e.g., "dvwa").
            source: How the credential was obtained.
            url: URL where this credential applies.

        Returns:
            Credential UUID.
        """
        cred_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        await self._state._conn.execute(
            "INSERT INTO credentials "
            "(id, engagement_id, username, password, technology, source, url, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (cred_id, engagement_id, username, password, technology, source, url, now),
        )
        await self._state._conn.commit()
        logger.debug("Added credential %s:%s for %s", username, "***", technology)
        return cred_id

    async def get(
        self,
        engagement_id: str,
        technology: str | None = None,
    ) -> list[Credential]:
        """Retrieve credentials for an engagement.

        Args:
            engagement_id: Engagement UUID.
            technology: If provided, filter by technology.

        Returns:
            List of Credential models.
        """
        if technology:
            query = (
                "SELECT * FROM credentials "
                "WHERE engagement_id=? AND technology=? ORDER BY created_at"
            )
            params: tuple[Any, ...] = (engagement_id, technology)
        else:
            query = "SELECT * FROM credentials WHERE engagement_id=? ORDER BY created_at"
            params = (engagement_id,)

        async with self._state._conn.execute(query, params) as cursor:
            rows = await cursor.fetchall()

        return [
            Credential(
                id=row["id"],
                engagement_id=row["engagement_id"],
                username=row["username"],
                password=row["password"],
                technology=row["technology"],
                source=row["source"],
                url=row["url"],
                valid=None if row["valid"] is None else bool(row["valid"]),
                created_at=row["created_at"],
            )
            for row in rows
        ]

    async def mark_valid(self, credential_id: str) -> None:
        """Mark a credential as confirmed valid.

        Args:
            credential_id: Credential UUID.
        """
        await self._state._conn.execute(
            "UPDATE credentials SET valid=1 WHERE id=?", (credential_id,)
        )
        await self._state._conn.commit()

    async def mark_invalid(self, credential_id: str) -> None:
        """Mark a credential as confirmed invalid.

        Args:
            credential_id: Credential UUID.
        """
        await self._state._conn.execute(
            "UPDATE credentials SET valid=0 WHERE id=?", (credential_id,)
        )
        await self._state._conn.commit()

    async def get_all_valid(self, engagement_id: str) -> list[Credential]:
        """Return all confirmed-valid credentials for an engagement.

        Args:
            engagement_id: Engagement UUID.

        Returns:
            List of Credential models where valid=True.
        """
        async with self._state._conn.execute(
            "SELECT * FROM credentials WHERE engagement_id=? AND valid=1 ORDER BY created_at",
            (engagement_id,),
        ) as cursor:
            rows = await cursor.fetchall()

        return [
            Credential(
                id=row["id"],
                engagement_id=row["engagement_id"],
                username=row["username"],
                password=row["password"],
                technology=row["technology"],
                source=row["source"],
                url=row["url"],
                valid=True,
                created_at=row["created_at"],
            )
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Default credentials
    # ------------------------------------------------------------------

    def get_defaults_for_technology(self, technology: str) -> list[dict[str, str]]:
        """Return preloaded default credentials for a technology.

        Also includes generic defaults that apply to any technology.

        Args:
            technology: Technology name (case-insensitive, e.g., "dvwa", "tomcat").

        Returns:
            List of dicts with 'username' and 'password' keys.
        """
        tech_lower = technology.lower().replace(" ", "_").replace("-", "_")
        results: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()

        for cred in _DEFAULT_CREDENTIALS:
            if cred["technology"] in (tech_lower, "generic"):
                key = (cred["username"], cred["password"])
                if key not in seen:
                    seen.add(key)
                    results.append(
                        {"username": cred["username"], "password": cred["password"]}
                    )

        return results

    async def seed_defaults(self, engagement_id: str, technology: str) -> list[str]:
        """Seed the store with default credentials for a technology.

        Adds all matching default credentials to the database so they
        can be tracked and validated.

        Args:
            engagement_id: Engagement UUID.
            technology: Technology name.

        Returns:
            List of created credential IDs.
        """
        defaults = self.get_defaults_for_technology(technology)
        ids: list[str] = []
        for cred in defaults:
            cred_id = await self.add(
                engagement_id,
                username=cred["username"],
                password=cred["password"],
                technology=technology.lower(),
                source="default",
            )
            ids.append(cred_id)
        return ids
