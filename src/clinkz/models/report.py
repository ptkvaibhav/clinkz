"""Report data models.

PentestReport aggregates all findings, targets, and metadata into
a structure that the ReportGenerator can render to HTML/PDF/JSON.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from clinkz.models.finding import Finding, Severity
from clinkz.models.target import Host


class ReportFormat(StrEnum):
    """Supported output formats for the report renderer."""

    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    MARKDOWN = "markdown"


class ExecutiveSummary(BaseModel):
    """High-level summary written for a non-technical audience.

    Attributes:
        overview: 2–4 sentence description of the engagement and overall risk.
        risk_rating: Overall risk rating (Critical / High / Medium / Low).
        critical_count: Number of critical findings.
        high_count: Number of high severity findings.
        medium_count: Number of medium severity findings.
        low_count: Number of low severity findings.
        info_count: Number of informational findings.
        key_findings: Bullet-point list of the most important discoveries.
        recommendations: Prioritised remediation recommendations.
    """

    overview: str
    risk_rating: str
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    key_findings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)

    @classmethod
    def from_findings(cls, overview: str, findings: list[Finding]) -> ExecutiveSummary:
        """Compute severity counts from a list of findings.

        Args:
            overview: Pre-written overview paragraph.
            findings: Validated findings list.

        Returns:
            ExecutiveSummary with counts populated.
        """
        counts = {s: 0 for s in Severity}
        for f in findings:
            counts[f.severity] += 1

        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for s in severity_order:
            if counts[s] > 0:
                risk_rating = s.value.capitalize()
                break
        else:
            risk_rating = "Informational"

        return cls(
            overview=overview,
            risk_rating=risk_rating,
            critical_count=counts[Severity.CRITICAL],
            high_count=counts[Severity.HIGH],
            medium_count=counts[Severity.MEDIUM],
            low_count=counts[Severity.LOW],
            info_count=counts[Severity.INFO],
        )


class PentestReport(BaseModel):
    """Complete penetration test report.

    This is the final output of a pentest engagement.
    Passed to the ReportRenderer to produce HTML/PDF.

    Attributes:
        id: Auto-generated UUID.
        engagement_name: Name of the engagement.
        target_scope: List of scope strings for display.
        test_start: When testing began.
        test_end: When testing concluded.
        generated_at: Timestamp of report generation.
        executive_summary: High-level summary (populated by ReportAgent).
        hosts: All discovered hosts.
        findings: Validated findings (Critic-approved only).
        methodology: Narrative describing the testing approach.
        appendices: Optional extra sections keyed by title.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    engagement_name: str
    target_scope: list[str] = Field(default_factory=list)
    test_start: datetime
    test_end: datetime
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    executive_summary: ExecutiveSummary | None = None
    hosts: list[Host] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    methodology: str = ""
    appendices: dict[str, str] = Field(default_factory=dict)

    @property
    def finding_counts(self) -> dict[str, int]:
        """Return a dict of severity → count for all findings."""
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
