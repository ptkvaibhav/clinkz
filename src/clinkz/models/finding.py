"""Vulnerability finding model.

A Finding is the primary output of the pentest. The Critic Agent
validates each finding before it reaches the report.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """CVSS-aligned severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    """Lifecycle state of a finding."""

    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"


class Finding(BaseModel):
    """A single vulnerability finding discovered during a pentest.

    Attributes:
        id: Auto-generated UUID.
        title: Short, descriptive title (e.g., "SQL Injection in /api/users").
        description: Detailed technical description of the vulnerability.
        severity: CVSS-aligned severity level.
        status: Validation state (new → confirmed or false_positive).
        target: Affected host/URL.
        evidence: List of evidence strings (request/response snippets, screenshots paths).
        cvss_score: Optional CVSS base score (0.0 – 10.0).
        cve_ids: Associated CVE identifiers, if any.
        references: URLs to CVE entries, writeups, or documentation.
        remediation: Recommended fix.
        discovered_at: Timestamp when the finding was created.
        validated_at: Timestamp when the Critic Agent validated it.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    severity: Severity
    status: FindingStatus = FindingStatus.NEW
    target: str
    evidence: list[str] = Field(default_factory=list)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cve_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    remediation: str = ""
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    validated_at: datetime | None = None
