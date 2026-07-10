"""Vulnerability finding model.

A Finding is the primary output of the pentest. The Critic Agent
validates each finding before it reaches the report.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from clinkz.models.scan import ParamLocation


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
        endpoint_method: HTTP method the endpoint expects (GET/POST/PUT/...).
        endpoint_content_type: Request content-type for body-bearing
            endpoints (e.g. ``application/json``), or None.
        param_locations: Per-param injection location (query/json_body/
            form_body/path). A name absent from this map defaults to
            ``query`` (or ``path`` when the URL templates it). Sourced from
            the discovered :class:`~clinkz.models.scan.Endpoint`, never from
            LLM JSON, so it cannot drift.
        tier: 1 (universal), 2 (tech-matched), 3 (experimental/research).
        playbook_entry_id: FK to persistent KB playbook_entries (tier 2/3).
        technique_name: Human-readable technique name.
        technique_steps: Steps from research runbook (tier 3).
        priority: Execution priority (lower = run first).
        carrier_constraints: Per-instance probe-carrier constraints from a
            discovery-engine proof obligation (e.g. ``align_host_with_injected_
            url_host``). Threaded onto the ``PageAnalysis`` so the shared request
            builder honours them; empty for LLM/deterministic-planned tasks
            (unchanged behaviour). Sourced from the hypothesis, never LLM JSON.
    """

    test_method: str
    endpoint_url: str
    endpoint_params: list[str] = Field(default_factory=list)
    endpoint_method: str = "GET"
    endpoint_content_type: str | None = None
    param_locations: dict[str, ParamLocation] = Field(default_factory=dict)
    tier: int = Field(ge=1, le=3)
    playbook_entry_id: int | None = None
    technique_name: str = ""
    technique_steps: list[str] = Field(default_factory=list)
    priority: int = 0
    carrier_constraints: list[str] = Field(default_factory=list)


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
        false_positive_suspects: Findings the LLM thinks may be false positives.
            Each entry is a ``{"id": <finding-id>, "reason": <why>}`` dict. The
            live LLM emits these as structured objects (not bare id strings), so
            the field is typed ``list[dict]`` — the same str-vs-dict drift that
            previously broke ``chaining_opportunities`` / ``finding_ids``. A
            ``before`` validator coerces a legacy ``list[str]`` (bare ids) into
            this shape so both variants parse.
        retry_targets: Tasks to retry with adapted payloads.
        chaining_opportunities: Descriptions of how findings can be chained.
            Each entry is heterogeneous — e.g. a ``description`` string plus a
            ``finding_ids`` list — so values are typed ``Any`` rather than
            ``str`` (the LLM legitimately emits a list for ``finding_ids``).
        coverage_summary: Human-readable summary of test coverage.
    """

    false_positive_suspects: list[dict[str, Any]] = Field(default_factory=list)
    retry_targets: list[ExploitTask] = Field(default_factory=list)
    chaining_opportunities: list[dict[str, Any]] = Field(default_factory=list)
    coverage_summary: str = ""

    @field_validator("false_positive_suspects", mode="before")
    @classmethod
    def _coerce_fp_suspects(cls, value: Any) -> list[dict[str, Any]]:
        """Normalise false-positive suspects to ``[{"id", "reason"}, ...]``.

        Accepts the two shapes the LLM produces in the wild:

          * ``["id1", "id2"]``           — bare finding-id strings (legacy)
          * ``[{"id": ..., "reason": ...}]`` — structured objects (current)

        Both are mapped to ``{"id": str, "reason": str}`` dicts. ``finding_id``
        is accepted as an alias for ``id``. Entries without a usable id are
        dropped rather than raising, so a single malformed element can never
        void the whole post-run analysis.
        """
        if not isinstance(value, list):
            return []
        coerced: list[dict[str, Any]] = []
        for item in value:
            if isinstance(item, str):
                if item:
                    coerced.append({"id": item, "reason": ""})
            elif isinstance(item, dict):
                fid = item.get("id") or item.get("finding_id") or item.get("finding")
                if fid:
                    coerced.append({"id": str(fid), "reason": str(item.get("reason") or "")})
        return coerced


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
