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


# ---------------------------------------------------------------------------
# Exploit Agent v2 models
# ---------------------------------------------------------------------------


class ExploitTask(BaseModel):
    """A single exploit task planned by the LLM.

    Attributes:
        test_method: Name of the _test_* method to call (e.g. "_test_sqli").
        endpoint_url: URL of the endpoint to test.
        endpoint_params: Parameter names on the endpoint.
        tier: 1 (universal), 2 (tech-matched), 3 (experimental/research).
        playbook_entry_id: FK to persistent KB playbook_entries (tier 2/3).
        technique_name: Human-readable technique name.
        technique_steps: Steps from research runbook (tier 3).
        priority: Execution priority (lower = run first).
    """

    test_method: str
    endpoint_url: str
    endpoint_params: list[str] = Field(default_factory=list)
    tier: int = Field(ge=1, le=3)
    playbook_entry_id: int | None = None
    technique_name: str = ""
    technique_steps: list[str] = Field(default_factory=list)
    priority: int = 0


class ExploitPlan(BaseModel):
    """Ordered plan of exploit tasks grouped by tier.

    Attributes:
        tasks: All planned exploit tasks in priority order.
        tier1_count: Number of universal (always-run) tasks.
        tier2_count: Number of technology-matched tasks.
        tier3_count: Number of experimental/research tasks.
    """

    tasks: list[ExploitTask] = Field(default_factory=list)
    tier1_count: int = 0
    tier2_count: int = 0
    tier3_count: int = 0


class ExploitAnalysis(BaseModel):
    """LLM analysis of exploit results — identifies retries and chaining.

    Attributes:
        false_positive_suspects: Finding IDs the LLM thinks may be false positives.
        retry_targets: Tasks to retry with adapted payloads.
        chaining_opportunities: Descriptions of how findings can be chained.
        coverage_summary: Human-readable summary of test coverage.
    """

    false_positive_suspects: list[str] = Field(default_factory=list)
    retry_targets: list[ExploitTask] = Field(default_factory=list)
    chaining_opportunities: list[dict[str, str]] = Field(default_factory=list)
    coverage_summary: str = ""


class ExploitResult(BaseModel):
    """Final output of the v2 exploit agent.

    Consumed by the Orchestrator, Critic Agent, and Report Agent.

    Attributes:
        findings: All vulnerability findings discovered.
        plan: The exploit plan that was executed.
        analysis: LLM analysis of the results.
        total_tests_run: Number of _test_* invocations.
        total_findings: Number of findings discovered.
        by_severity: Finding counts by severity level.
        kb_results_recorded: Number of technique results written to persistent KB.
        stopped_early: True when the phase stopped dispatching new tasks at the
            cooperative deadline before exhausting its plan. Findings are
            persisted incrementally, so an early stop still yields a complete,
            queryable result in the state store.
        timestamp: When the exploit phase completed.
    """

    findings: list[Finding] = Field(default_factory=list)
    plan: ExploitPlan = Field(default_factory=ExploitPlan)
    analysis: ExploitAnalysis = Field(default_factory=ExploitAnalysis)
    total_tests_run: int = 0
    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    kb_results_recorded: int = 0
    stopped_early: bool = False
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
