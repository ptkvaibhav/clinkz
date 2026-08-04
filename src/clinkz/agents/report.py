"""Report agent — generates a client-ready pentest report from engagement data.

Zero LLM calls. Pulls everything from the state store and the engagement inputs,
and writes:
  - JSON file with structured finding data
  - Markdown file with a human-readable deliverable

The report has four parts, and the fourth is the one that makes it professional:

1. **Header** — who authorized this, under what reference, over what window,
   against what scope (in AND out), with which rules of engagement.
2. **Findings** — severity, CVSS, endpoint, raw PoC evidence, remediation.
3. **Unconfirmed leads** — a different TYPE, in their own sections, never
   counted in the totals.
4. **What was NOT tested** — out-of-scope hosts, techniques the client did not
   permit, classes with no client-side oracle (DOM-XSS, CSP enforcement),
   classes with no methodology at all (Insecure CAPTCHA), actions the safety
   rails refused, and any halt that cut coverage short.

Part 4 exists because a client reading "no findings" is entitled to know whether
that means "we looked and it is sound" or "we could not look". Every entry is
generated from the class registry and the run's own action log, so it cannot
drift out of date the way a hand-written limitations section does.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from clinkz.agents.base import BaseAgent

if TYPE_CHECKING:
    from clinkz.knowledge.query import KnowledgeBase
from clinkz.llm.base import LLMClient
from clinkz.models.engagement import AuthorizationRecord, EngagementWindow
from clinkz.models.finding import (
    CrossServiceResearchLead,
    Finding,
    FindingStatus,
    Severity,
    UnprovenExploitLead,
)
from clinkz.models.report import (
    ExecutiveSummary,
    NotTestedCategory,
    NotTestedItem,
    PentestReport,
)
from clinkz.models.scope import EngagementScope
from clinkz.models.target import Host
from clinkz.models.vuln_classes import (
    UNIMPLEMENTED_CLASSES,
    VULN_CLASSES,
    ConfirmationCapability,
    for_finding,
)
from clinkz.safety.action_log import ActionLog, RefusalTally
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase

logger = logging.getLogger(__name__)


def _parse_authorization(raw: Any) -> AuthorizationRecord | None:
    """Rebuild the authorization record from the orchestrator's handoff dict."""
    if not isinstance(raw, dict):
        return None
    try:
        return AuthorizationRecord.model_validate(raw)
    except Exception as exc:  # noqa: BLE001 — a bad header must not lose the findings
        logger.warning("Could not parse the authorization record for the report: %s", exc)
        return None


def _parse_window(raw: Any) -> EngagementWindow | None:
    """Rebuild the engagement window from the orchestrator's handoff dict."""
    if not isinstance(raw, dict):
        return None
    try:
        return EngagementWindow.model_validate(raw)
    except Exception as exc:  # noqa: BLE001 — same reason as above
        logger.warning("Could not parse the engagement window for the report: %s", exc)
        return None


_PROMPT_PATH = Path(__file__).parent / "prompts" / "report_system.md"
_SYSTEM_PROMPT: str = _PROMPT_PATH.read_text(encoding="utf-8")


class ReportAgent(BaseAgent):
    """Simple report agent — zero LLM calls.

    Pulls findings from the state store, formats them into a JSON file
    and a Markdown file.  No executive summary, no attack narrative,
    no multi-pass LLM.  Completes in < 30 seconds.

    Args:
        llm: LLM client (accepted for interface compat but NOT used).
        tools: Unused.
        scope: Engagement scope for display in the report.
        state: SQLite state store to read findings/targets from.
        engagement_id: UUID of the active engagement.
    """

    def __init__(
        self,
        llm: LLMClient,
        tools: list[ToolBase],
        scope: EngagementScope,
        state: StateStore,
        engagement_id: str,
        knowledge_base: KnowledgeBase | None = None,
        **kwargs: Any,
    ) -> None:
        # Accept and discard outbox/extra kwargs for backward compat
        kwargs.pop("outbox", None)
        super().__init__(
            llm=llm,
            tools=tools,
            scope=scope,
            state=state,
            engagement_id=engagement_id,
            knowledge_base=knowledge_base,
            **kwargs,
        )

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "report"

    @property
    def system_prompt(self) -> str:
        return _SYSTEM_PROMPT

    # ------------------------------------------------------------------
    # Entry point — zero LLM calls
    # ------------------------------------------------------------------

    async def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Generate a simple report from engagement state data.

        Pulls all findings from the state store and writes, under
        ``outputs/<engagement_id>/``:
        - ``report_<engagement_id>.json`` — structured finding data
        - ``report_<engagement_id>.md`` — human-readable markdown

        No LLM calls.  No executive summary.  No attack narrative.

        Args:
            input_data: Accepts optional ``engagement_id``, ``engagement_name``.

        Returns:
            Dict with ``report`` (PentestReport dict), ``json_path``,
            ``markdown_path``, and ``status``.
        """
        engagement_id = input_data.get("engagement_id", self.engagement_id)
        engagement_name = input_data.get("engagement_name", "Penetration Test")
        scope_values = [str(e.value) for e in self.scope.targets]

        now = datetime.now(UTC)
        test_start_raw = input_data.get("test_start")
        test_end_raw = input_data.get("test_end")
        test_start = datetime.fromisoformat(test_start_raw) if test_start_raw else now
        test_end = datetime.fromisoformat(test_end_raw) if test_end_raw else now

        self._logger.info(
            "ReportAgent starting (simple mode) for '%s' (%s)",
            engagement_name,
            engagement_id,
        )

        # Pull engagement data from state store
        findings_raw = await self.state.get_findings(engagement_id, validated_only=False)
        targets_raw = await self.state.get_targets(engagement_id)
        # Research-leads live in their OWN table (design §5), read into separate
        # sections — never merged into findings, never counted in coverage. The
        # table holds two structurally different lead types, told apart by the
        # ``lead_kind`` discriminator.
        leads_raw = await self.state.get_research_leads(engagement_id)

        self._logger.info(
            "Loaded %d findings, %d targets, %d research-leads",
            len(findings_raw),
            len(targets_raw),
            len(leads_raw),
        )

        # Parse Finding models. A finding the engagement itself flagged as a
        # suspected false positive is NOT rendered as a finding: the Exploit
        # phase already demotes those to unproven leads (the G10 emission
        # inversion), and this is the second, independent layer at the report
        # chokepoint — so a row written by an older build, a replay, or any
        # future path that sets the status cannot reach ``findings[]`` and be
        # counted in the totals.
        finding_models: list[Finding] = []
        suppressed = 0
        for fd in findings_raw:
            try:
                finding = Finding.model_validate(fd)
            except Exception as exc:
                self._logger.warning("Could not parse finding '%s': %s", fd.get("id"), exc)
                continue
            if finding.status == FindingStatus.FALSE_POSITIVE:
                suppressed += 1
                self._logger.warning(
                    "Excluding finding '%s' (%s) from the report — status=false_positive; "
                    "a finding the engagement believes is a false positive is never emitted",
                    finding.id,
                    finding.title,
                )
                continue
            finding_models.append(finding)
        if suppressed:
            self._logger.info("Report: %d false-positive finding(s) excluded", suppressed)

        # Parse Host models
        host_models: list[Host] = []
        for td in targets_raw:
            try:
                host_models.append(Host.model_validate(td))
            except Exception as exc:
                self._logger.warning("Could not parse host '%s': %s", td.get("id"), exc)

        # Parse the lead models (design §5) — DIFFERENT types than Finding, so they
        # cannot be rendered in the confirmed-findings section. ``lead_kind``
        # discriminates the cross-service chains from the single-service unproven
        # candidates; a row written before the discriminator existed defaults to
        # ``cross_service``.
        lead_models: list[CrossServiceResearchLead] = []
        unproven_models: list[UnprovenExploitLead] = []
        for ld in leads_raw:
            kind = ld.get("lead_kind") or "cross_service"
            try:
                if kind == "unproven_exploit":
                    unproven_models.append(UnprovenExploitLead.model_validate(ld))
                else:
                    lead_models.append(CrossServiceResearchLead.model_validate(ld))
            except Exception as exc:
                self._logger.warning("Could not parse research-lead (kind=%s): %s", kind, exc)

        # Build severity counts for executive summary (no LLM)
        severity_counts = {s: 0 for s in Severity}
        for f in finding_models:
            severity_counts[f.severity] += 1

        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        risk_rating = "Informational"
        for s in severity_order:
            if severity_counts[s] > 0:
                risk_rating = s.value.capitalize()
                break

        exec_summary = ExecutiveSummary(
            overview=(
                f"Penetration test of {', '.join(scope_values)}. "
                f"{len(finding_models)} findings identified."
            ),
            risk_rating=risk_rating,
            critical_count=severity_counts[Severity.CRITICAL],
            high_count=severity_counts[Severity.HIGH],
            medium_count=severity_counts[Severity.MEDIUM],
            low_count=severity_counts[Severity.LOW],
            info_count=severity_counts[Severity.INFO],
        )

        # Attach remediation to any finding the methodology emitted without it.
        # The methodologies emit PROOF, not advice; the advice lives once per
        # class in the registry, so it stays reviewable in one place instead of
        # being copy-pasted across twenty emit sites.
        for finding in finding_models:
            if not finding.remediation:
                vuln_class = for_finding(finding.title, finding.description)
                if vuln_class and vuln_class.remediation:
                    finding.remediation = vuln_class.remediation

        authorization = _parse_authorization(input_data.get("authorization"))
        window = _parse_window(input_data.get("engagement_window"))
        scope_in = list(input_data.get("scope_in") or []) or scope_values
        scope_out = list(input_data.get("scope_out") or [])
        safety = dict(input_data.get("safety") or {})
        authentication = dict(input_data.get("authentication") or {})

        report = PentestReport(
            engagement_name=engagement_name,
            target_scope=scope_in,
            test_start=test_start,
            test_end=test_end,
            executive_summary=exec_summary,
            hosts=host_models,
            findings=finding_models,
            research_leads=lead_models,
            unproven_leads=unproven_models,
            authorization=authorization,
            engagement_window=window,
            rules_of_engagement=list(input_data.get("rules_of_engagement") or []),
            excluded_scope=scope_out,
            not_tested=self._build_not_tested(
                engagement_id=engagement_id,
                authorization=authorization,
                scope_out=scope_out,
                safety=safety,
                authentication=authentication,
            ),
            safety_summary=safety,
            authentication=authentication,
        )

        report_dict = report.model_dump(mode="json")

        # Reports live alongside the rest of the engagement artifacts under
        # ``outputs/<engagement_id>/`` (same convention as trace.jsonl and the
        # tool-invocation records). Writing to the cwd would litter the repo
        # root with per-engagement dumps.
        output_dir = Path("outputs") / engagement_id
        output_dir.mkdir(parents=True, exist_ok=True)

        # Write JSON output
        json_path = output_dir / f"report_{engagement_id}.json"
        json_path.write_text(json.dumps(report_dict, indent=2), encoding="utf-8")
        self._logger.info("JSON report written to %s", json_path)

        # Write Markdown output
        md_path = output_dir / f"report_{engagement_id}.md"
        md_path.write_text(
            self._render_markdown(report, finding_models),
            encoding="utf-8",
        )
        self._logger.info("Markdown report written to %s", md_path)

        self._logger.info(
            "Report complete: %d findings, risk_rating=%s",
            len(report.findings),
            risk_rating,
        )

        return {
            "report": report_dict,
            "json_path": str(json_path),
            "markdown_path": str(md_path),
            "status": "complete",
        }

    # ------------------------------------------------------------------
    # "What was NOT tested"
    # ------------------------------------------------------------------

    def _build_not_tested(
        self,
        *,
        engagement_id: str,
        authorization: AuthorizationRecord | None,
        scope_out: list[str],
        safety: dict[str, Any],
        authentication: dict[str, Any],
    ) -> list[NotTestedItem]:
        """Assemble the honest-limits section from the run's own artifacts.

        Generated, never written by hand: the class registry supplies the oracle
        and methodology gaps, the authorization record supplies the techniques
        the client withheld, the action log supplies what the safety rails
        actually refused, and the governor supplies any halt. A hand-written
        limitations section rots; this one cannot disagree with the run.

        Args:
            engagement_id: Engagement UUID, for reading the action log.
            authorization: The authorization record, when present.
            scope_out: Explicitly excluded scope entries.
            safety: The governor's stats dict.
            authentication: The authentication summary dict.

        Returns:
            One :class:`NotTestedItem` per limitation, most client-relevant first.
        """
        items: list[NotTestedItem] = []

        for entry in scope_out:
            items.append(
                NotTestedItem(
                    item=entry,
                    category=NotTestedCategory.OUT_OF_SCOPE,
                    reason=(
                        "Explicitly excluded from the engagement scope. No request of "
                        "any kind was sent to it."
                    ),
                )
            )

        # Techniques the client did not authorize.
        if authorization is not None and not authorization.permits_all:
            for vuln_class in VULN_CLASSES:
                if not authorization.permits(vuln_class.key):
                    items.append(
                        NotTestedItem(
                            item=vuln_class.label,
                            category=NotTestedCategory.NOT_PERMITTED,
                            reason=(
                                "Not present in the authorized permitted-technique list "
                                f"({authorization.authorization_reference})."
                            ),
                        )
                    )

        # Classes this engine cannot confirm, and classes it does not implement.
        for vuln_class in VULN_CLASSES:
            if vuln_class.capability is ConfirmationCapability.CLIENT_SIDE_ORACLE_REQUIRED:
                items.append(
                    NotTestedItem(
                        item=vuln_class.label,
                        category=NotTestedCategory.NO_CLIENT_SIDE_ORACLE,
                        reason=vuln_class.limitation,
                    )
                )
        for vuln_class in UNIMPLEMENTED_CLASSES:
            items.append(
                NotTestedItem(
                    item=vuln_class.label,
                    category=NotTestedCategory.NOT_IMPLEMENTED,
                    reason=vuln_class.limitation,
                )
            )

        # What the safety rails actually refused, from this run's action log.
        tally = RefusalTally.from_records(ActionLog.read(engagement_id))
        for category, count in sorted(tally.by_category.items()):
            example = tally.examples.get(category, "")
            items.append(
                NotTestedItem(
                    item=f"Actions classified as '{category}' ({count} refused)",
                    category=NotTestedCategory.DESTRUCTIVE_REFUSED,
                    reason=(
                        "The production safety rails refused these requests rather than "
                        "sending them to a live application"
                        + (f" (for example: {example})" if example else "")
                        + ". Testing them requires an explicit, supervised exception."
                    ),
                )
            )

        # Coverage cut short.
        if safety.get("halted"):
            items.append(
                NotTestedItem(
                    item="Remaining coverage after the engagement halted",
                    category=NotTestedCategory.ENGAGEMENT_HALTED,
                    reason=(
                        f"The engagement stopped early ({safety.get('halt_reason')}): "
                        f"{safety.get('halt_detail')}. Classes and endpoints not "
                        "reached before the halt were not tested."
                    ),
                )
            )

        # Access-control coverage without two principals to compare.
        if not authentication.get("authenticated"):
            items.append(
                NotTestedItem(
                    item="Authenticated application surface",
                    category=NotTestedCategory.UNAUTHENTICATED,
                    reason=(
                        "No authenticated session was established for this engagement, "
                        "so only the surface reachable without a login was tested. "
                        "Anything behind authentication was not examined."
                    ),
                )
            )
        elif not authentication.get("multi_role"):
            items.append(
                NotTestedItem(
                    item="Cross-role authorization (horizontal / vertical access control)",
                    category=NotTestedCategory.UNAUTHENTICATED,
                    reason=(
                        "Only one authenticated role was available. Proving that an "
                        "authorization boundary was crossed requires two principals to "
                        "compare, so access-control findings here are candidates rather "
                        "than confirmed boundary crossings."
                    ),
                )
            )

        return items

    # ------------------------------------------------------------------
    # Markdown renderer — no LLM
    # ------------------------------------------------------------------

    @staticmethod
    def _render_markdown(report: PentestReport, findings: list[Finding]) -> str:
        """Render a simple Markdown report.

        Args:
            report: The assembled PentestReport.
            findings: Parsed Finding models.

        Returns:
            Markdown string.
        """
        lines: list[str] = [f"# Penetration Test Report — {report.engagement_name}", ""]
        ReportAgent._render_header(lines, report)
        lines.extend(
            [
                "## Summary",
                "",
                f"- **Risk rating:** "
                f"{report.executive_summary.risk_rating if report.executive_summary else 'N/A'}",
                f"- **Confirmed findings:** {len(findings)}",
                f"- **Unconfirmed leads:** "
                f"{len(report.unproven_leads) + len(report.research_leads)} "
                "(not counted above)",
                "",
                "---",
                "",
            ]
        )

        if not findings:
            lines.extend(
                [
                    "## Findings",
                    "",
                    "No confirmed findings. Read the *What was NOT tested* section "
                    "below before treating this as a clean result — it states exactly "
                    "which parts of the application this engagement was able to "
                    "examine and which it was not.",
                    "",
                    "---",
                    "",
                ]
            )
            ReportAgent._render_research_leads(lines, report.research_leads)
            ReportAgent._render_unproven_leads(lines, report.unproven_leads)
            ReportAgent._render_not_tested(lines, report)
            return "\n".join(lines)

        lines.extend(["## Findings", ""])

        for i, f in enumerate(findings, 1):
            cvss_str = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "N/A"
            lines.extend(
                [
                    f"## {i}. {f.title}",
                    "",
                    f"- **Severity:** {f.severity.value.upper()}",
                    f"- **CVSS:** {cvss_str}",
                    f"- **Endpoint:** {f.target}",
                    "",
                ]
            )

            # PoC evidence (request + response)
            if f.evidence:
                lines.append("**PoC:**")
                lines.append("```")
                for ev in f.evidence:
                    lines.append(ev)
                lines.append("```")
                lines.append("")

            # One-line remediation
            lines.append(f"**Remediation:** {f.remediation or 'N/A'}")
            lines.extend(["", "---", ""])

        ReportAgent._render_research_leads(lines, report.research_leads)
        ReportAgent._render_unproven_leads(lines, report.unproven_leads)
        ReportAgent._render_not_tested(lines, report)
        return "\n".join(lines)

    @staticmethod
    def _render_header(lines: list[str], report: PentestReport) -> None:
        """Render the authorization, window, scope, and rails header.

        This block is the difference between a report and a scanner dump. A
        client-facing document has to be able to state on its first page who
        authorized the test, under what reference, over what window, and what
        was deliberately left alone.
        """
        record = report.authorization
        lines.extend(["## Authorization", ""])
        if record is None:
            lines.extend(
                [
                    "> **No authorization record was attached to this engagement.** "
                    "This report should not be treated as the output of an authorized "
                    "test.",
                    "",
                ]
            )
        else:
            lines.extend(
                [
                    f"- **Authorized by:** {record.authorizing_party} ({record.authorizing_role})",
                    f"- **Contact:** {record.authorizing_contact}",
                    f"- **Authorization reference:** {record.authorization_reference}",
                    f"- **Emergency contact:** {record.emergency_contact}",
                    "- **Permitted techniques:** "
                    + (
                        "all techniques"
                        if record.permits_all
                        else ", ".join(record.permitted_techniques)
                    ),
                ]
            )
            if record.notes:
                lines.append(f"- **Notes:** {record.notes}")
            lines.append("")

        window = report.engagement_window
        lines.extend(
            [
                "## Engagement window",
                "",
                (
                    f"- **Authorized window:** {window.start.isoformat()} → "
                    f"{window.end.isoformat()}"
                    if window is not None
                    else "- **Authorized window:** none agreed"
                ),
                f"- **Testing performed:** {report.test_start.isoformat()} → "
                f"{report.test_end.isoformat()}",
                "",
                "## Scope",
                "",
                "**In scope (tested):**",
                "",
            ]
        )
        lines.extend([f"- {entry}" for entry in report.target_scope] or ["- (none)"])
        lines.extend(["", "**Out of scope (never contacted):**", ""])
        lines.extend([f"- {entry}" for entry in report.excluded_scope] or ["- (none declared)"])

        if report.rules_of_engagement:
            lines.extend(["", "**Rules of engagement:**", ""])
            lines.extend([f"- {rule}" for rule in report.rules_of_engagement])

        auth = report.authentication
        if auth:
            lines.extend(["", "## Authentication", ""])
            if auth.get("authenticated"):
                assertion = auth.get("assertion") or {}
                lines.extend(
                    [
                        f"- **Mechanism:** {auth.get('mechanism', 'unknown')}",
                        f"- **Roles authenticated:** "
                        f"{', '.join(auth.get('roles') or []) or '(none)'}",
                        "- **Authenticated state:** PROVEN — "
                        f"`{assertion.get('discriminator', '?')}` at "
                        f"{assertion.get('url', '?')} "
                        f"(authenticated HTTP {assertion.get('authenticated_status')}, "
                        f"anonymous control HTTP {assertion.get('anonymous_status')})",
                    ]
                )
                for evidence in assertion.get("evidence") or []:
                    lines.append(f"  - {evidence}")
                if auth.get("session_losses_detected"):
                    lines.append(
                        f"- **Session maintenance:** "
                        f"{auth.get('session_losses_detected')} loss signal(s) detected, "
                        f"{auth.get('reauthentications')} re-authentication(s) performed"
                    )
            else:
                lines.append(
                    "- **Authenticated state:** NOT established — this engagement "
                    "examined only the surface reachable without a login."
                )

        safety = report.safety_summary
        if safety:
            lines.extend(
                [
                    "",
                    "## Testing conduct",
                    "",
                    f"- **Rate limit:** {safety.get('max_requests_per_second')} requests/second, "
                    f"{safety.get('max_concurrent_requests')} concurrent",
                    f"- **State-changing requests sent:** {safety.get('state_changing_sent', 0)}",
                    f"- **Requests refused by the safety rails:** "
                    f"{safety.get('state_changing_refused', 0)}",
                ]
            )
            if safety.get("halted"):
                lines.append(
                    f"- **ENGAGEMENT HALTED** ({safety.get('halt_reason')}): "
                    f"{safety.get('halt_detail')}"
                )
        lines.extend(["", "---", ""])

    @staticmethod
    def _render_not_tested(lines: list[str], report: PentestReport) -> None:
        """Render the honest-limits section.

        Grouped by reason so a client can see at a glance which gaps are their
        decision (out of scope, techniques not permitted) and which are this
        engine's (no client-side oracle, no methodology).
        """
        lines.extend(
            [
                "## What was NOT tested",
                "",
                "> Absence of a finding is only meaningful where testing actually "
                "reached. Everything this engagement did **not** examine is listed "
                "here, with the reason. Items under *no client-side oracle* and "
                "*no methodology* are limitations of this tool and are candidates "
                "for manual review.",
                "",
            ]
        )
        if not report.not_tested:
            lines.extend(["Nothing was excluded from testing.", ""])
            return

        headings = {
            NotTestedCategory.OUT_OF_SCOPE: "Excluded by the client",
            NotTestedCategory.NOT_PERMITTED: "Techniques not authorized",
            NotTestedCategory.NO_CLIENT_SIDE_ORACLE: ("Not confirmable — no client-side oracle"),
            NotTestedCategory.NOT_IMPLEMENTED: "Not confirmable — no methodology",
            NotTestedCategory.DESTRUCTIVE_REFUSED: ("Refused by the production safety rails"),
            NotTestedCategory.ENGAGEMENT_HALTED: "Cut short when the engagement halted",
            NotTestedCategory.UNAUTHENTICATED: "Limited by the sessions available",
        }
        for category, heading in headings.items():
            group = [item for item in report.not_tested if item.category == category]
            if not group:
                continue
            lines.extend([f"### {heading}", ""])
            for item in group:
                lines.append(f"- **{item.item}** — {item.reason}")
            lines.append("")
        lines.extend(["---", ""])

    @staticmethod
    def _render_unproven_leads(lines: list[str], leads: list[UnprovenExploitLead]) -> None:
        """Render the 'Unproven exploitation leads (UNCONFIRMED)' section.

        Structurally separate from the confirmed-findings loop for the same
        reason as :meth:`_render_research_leads`: these are a different type,
        rendered under their own heading, explicitly marked UNCONFIRMED, and
        never counted in the finding totals. Each lead states what WAS observed
        and what was NOT — so a reader can see exactly where the evidence stops.
        """
        if not leads:
            return
        lines.extend(
            [
                "## Unproven exploitation leads (candidates — UNCONFIRMED)",
                "",
                "> These are **reachability observations whose defining security effect "
                "was never witnessed**. They are **NOT findings**, are **not counted** "
                "in the totals above, and no exploitation is claimed. Each states what "
                "was observed and what confirming observation is missing.",
                "",
            ]
        )
        for i, lead in enumerate(leads, 1):
            lines.extend(
                [
                    f"### U{i}. {lead.claim}",
                    "",
                    f"- **Why unconfirmed:** {lead.why_unconfirmed}",
                    f"- **Endpoint:** {lead.endpoint}"
                    + (f"  (parameter: {lead.parameter})" if lead.parameter else ""),
                    f"- **Technique:** {lead.technique}",
                    "",
                    "**Raw evidence:**",
                    "```",
                    f"observed: {lead.raw_observation}",
                    f"missing:  {lead.missing_observation}",
                    "```",
                    "",
                    "---",
                    "",
                ]
            )

    @staticmethod
    def _render_research_leads(lines: list[str], leads: list[CrossServiceResearchLead]) -> None:
        """Render the dedicated 'Cross-service research leads (UNCONFIRMED)' section.

        Kept **structurally separate** from the confirmed-findings loop above
        (design §5): research-leads are a different type, rendered under their own
        heading, explicitly marked UNCONFIRMED and never counted in the finding
        totals. Each lead carries the candidate chain, why it stayed unconfirmed,
        and the RAW null result (the probe that was sent and the null observation)
        so the operator sees exactly what was tried.
        """
        if not leads:
            return
        lines.extend(
            [
                "## Cross-service research leads (candidate chains — UNCONFIRMED)",
                "",
                "> These are **plausible-but-unproven** A→B cross-service chains. They "
                "are **NOT findings**, are **not counted** in the totals above, and were "
                "**not confirmed** by an oracle co-located with service B. Each is an "
                "operator worklist item — investigate with credentials / network access.",
                "",
            ]
        )
        for i, lead in enumerate(leads, 1):
            lines.extend(
                [
                    f"### L{i}. {lead.candidate_chain}",
                    "",
                    f"- **Why unconfirmed:** {lead.why_unconfirmed}",
                    f"- **A endpoint:** {lead.a_endpoint}  (channel: {lead.a_channel})",
                    f"- **B target:** {lead.b_target}",
                    f"- **Topology source:** {lead.topology_source} "
                    f"(grade: {lead.reachability_grade}, conf: {lead.reach_confidence})",
                    "",
                    "**Raw null result:**",
                    "```",
                    f"probe: {lead.raw_probe}",
                    f"observation: {lead.raw_null_observation}",
                    "```",
                    "",
                    "---",
                    "",
                ]
            )
