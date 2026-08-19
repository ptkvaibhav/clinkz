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
from clinkz.config import outputs_root as configured_outputs_root

if TYPE_CHECKING:
    from clinkz.knowledge.query import KnowledgeBase
from clinkz.engagement.secrets import redact, redact_structure
from clinkz.llm.base import LLMClient
from clinkz.llm.degradation import degradation_summary
from clinkz.llm.spend import spend_summary
from clinkz.models.engagement import AuthorizationRecord, EngagementWindow
from clinkz.models.finding import (
    ChainResearchLead,
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
from clinkz.observability.ledger import get_active_ledger
from clinkz.observability.plan_alarms import plan_alarm_summary
from clinkz.observability.trace import get_active_trace_writer
from clinkz.safety.action_log import ActionLog, RefusalTally
from clinkz.safety.scope_refusals import scope_refusal_summary
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase

logger = logging.getLogger(__name__)


def _active_ledger_snapshot() -> dict[str, Any]:
    """The component ledger as it stands, or ``{}`` when none is installed.

    Read from the process-global active ledger rather than threaded through the
    report task's payload, for the same reason the trace writer is: a directly
    invoked ReportAgent — a smoke cell, a replay — has no engagement and must
    render exactly as it did before, with an empty section rather than a
    fabricated one.
    """
    ledger = get_active_ledger()
    if ledger is None:
        return {}
    try:
        return ledger.to_dict()
    except Exception as exc:  # noqa: BLE001 — a report must never fail on its metadata
        logger.warning("Component ledger snapshot failed: %s", exc)
        return {}


def _active_model_stamp() -> list[dict[str, str | int]]:
    """Which model served each LLM stage of this run, or ``[]`` when untraced.

    Read from the active trace writer for the same reason as the ledger above: a
    directly invoked ReportAgent has no engagement, and an empty stamp is the
    honest rendering of "this run made no traced LLM calls". Never reconstructed
    from configuration — see :meth:`TraceWriter.model_stamp`.
    """
    writer = get_active_trace_writer()
    if writer is None:
        return []
    try:
        return writer.model_stamp()
    except Exception as exc:  # noqa: BLE001 — a report must never fail on its metadata
        logger.warning("Model stamp snapshot failed: %s", exc)
        return []


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
        chain_lead_models: list[ChainResearchLead] = []
        for ld in leads_raw:
            kind = ld.get("lead_kind") or "cross_service"
            try:
                if kind == "unproven_exploit":
                    unproven_models.append(UnprovenExploitLead.model_validate(ld))
                elif kind == "chain":
                    chain_lead_models.append(ChainResearchLead.model_validate(ld))
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
            chain_leads=chain_lead_models,
            # The link-by-link view of every confirmed chain, handed in by the
            # orchestrator from the exploit result. Never a second source of
            # findings: each chain is already in ``findings``, emitted through
            # the same chokepoint, so this renders composition and counts nothing.
            confirmed_chains=[
                c for c in (input_data.get("confirmed_chains") or []) if isinstance(c, dict)
            ],
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
                graybox_source=dict(input_data.get("graybox_source") or {}),
                resumed_from=str(input_data.get("resumed_from") or ""),
            ),
            safety_summary=safety,
            authentication=authentication,
            component_ledger=_active_ledger_snapshot(),
            model_stamp=_active_model_stamp(),
            provider_degradation=degradation_summary(),
            scope_refusals=scope_refusal_summary(),
            llm_spend=spend_summary(),
            plan_coverage=plan_alarm_summary(),
            research_grounding=dict(input_data.get("research_grounding") or {}),
        )

        # The report is the artifact that actually reaches the client, so it
        # goes through the same redaction chokepoint as the trace and the
        # invocation records rather than being written raw. It used to be
        # written raw: every OTHER writer redacted, and the one document
        # designed to be handed over did not.
        report_dict = redact_structure(report.model_dump(mode="json"))

        # Reports live alongside the rest of the engagement artifacts under
        # ``outputs/<engagement_id>/`` (same convention as trace.jsonl and the
        # tool-invocation records). Writing to the cwd would litter the repo
        # root with per-engagement dumps.
        output_dir = configured_outputs_root() / engagement_id
        output_dir.mkdir(parents=True, exist_ok=True)

        # Write JSON output
        json_path = output_dir / f"report_{engagement_id}.json"
        json_path.write_text(json.dumps(report_dict, indent=2), encoding="utf-8")
        self._logger.info("JSON report written to %s", json_path)

        # Write Markdown output
        md_path = output_dir / f"report_{engagement_id}.md"
        md_path.write_text(
            redact(self._render_markdown(report, finding_models)),
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
        graybox_source: dict[str, Any] | None = None,
        resumed_from: str = "",
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
            graybox_source: What happened to the ``--source`` tree, when one was
                supplied. Empty on a black-box engagement.
            resumed_from: The engagement this deliverable was regenerated from,
                when ``clinkz scan --resume`` produced it.

        Returns:
            One :class:`NotTestedItem` per limitation, most client-relevant first.
        """
        items: list[NotTestedItem] = []

        # A supplied source tree that was NOT ingested. Stated first: it changes
        # how every other section should be read, because a gray-box engagement
        # that fell back to black-box produces artifacts identical to a run that
        # was never given source at all.
        graybox = graybox_source or {}
        if graybox and not graybox.get("ingested"):
            items.append(
                NotTestedItem(
                    item=(
                        "Gray-box source analysis of "
                        f"{graybox.get('source_dir', 'the source tree')}"
                    ),
                    category=NotTestedCategory.SOURCE_NOT_INGESTED,
                    reason=(
                        f"A source tree was supplied but was not ingested — "
                        f"{graybox.get('reason') or 'no reason recorded'}. The engagement "
                        "ran fully black-box: no source-derived hypothesis was tested, so "
                        "any vulnerability only reachable via a code path this engine "
                        "would have found in the source was not examined."
                    ),
                )
            )

        if resumed_from:
            items.append(
                NotTestedItem(
                    item="Everything not already proven when the original run stopped",
                    category=NotTestedCategory.ENGAGEMENT_HALTED,
                    reason=(
                        f"This deliverable was regenerated from the persisted state of "
                        f"engagement {resumed_from} rather than produced by a fresh test. "
                        "No request was sent to the target. It reports exactly what that "
                        "engagement had already proven and persisted before it stopped; "
                        "coverage it had not reached is absent here and was not retried."
                    ),
                )
            )

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
        unconfirmed = (
            len(report.unproven_leads) + len(report.research_leads) + len(report.chain_leads)
        )
        lines.extend(
            [
                "## Summary",
                "",
                f"- **Risk rating:** "
                f"{report.executive_summary.risk_rating if report.executive_summary else 'N/A'}",
                f"- **Confirmed findings:** {len(findings)}",
                f"- **Confirmed attack chains:** {len(report.confirmed_chains)} "
                "(each is also one of the findings above, never counted twice)",
                f"- **Unconfirmed leads:** {unconfirmed} (not counted above)",
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
            ReportAgent._render_chain_leads(lines, report.chain_leads)
            ReportAgent._render_not_tested(lines, report)
            ReportAgent._render_component_ledger(lines, report)
            ReportAgent._render_provider_degradation(lines, report)
            ReportAgent._render_scope_refusals(lines, report)
            ReportAgent._render_plan_coverage(lines, report)
            ReportAgent._render_research_grounding(lines, report)
            ReportAgent._render_llm_spend(lines, report)
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

        ReportAgent._render_chains(lines, report.confirmed_chains)
        ReportAgent._render_research_leads(lines, report.research_leads)
        ReportAgent._render_unproven_leads(lines, report.unproven_leads)
        ReportAgent._render_chain_leads(lines, report.chain_leads)
        ReportAgent._render_not_tested(lines, report)
        ReportAgent._render_component_ledger(lines, report)
        ReportAgent._render_provider_degradation(lines, report)
        ReportAgent._render_scope_refusals(lines, report)
        ReportAgent._render_plan_coverage(lines, report)
        ReportAgent._render_research_grounding(lines, report)
        ReportAgent._render_llm_spend(lines, report)
        return "\n".join(lines)

    @staticmethod
    def _render_scope_refusals(lines: list[str], report: PentestReport) -> None:
        """Render every out-of-scope target the run reached for, and refused.

        The most important control in an external engagement, and the one that
        used to leave no trace at all: the scope check raised, the crawler's
        fetch helper caught the error and returned ``None``, and nothing
        recorded that a third-party host had been reached for and stopped.

        Rendered on a clean run too. "No out-of-scope target was reached for"
        is a claim; an absent section is not.
        """
        stamp = report.scope_refusals
        if not stamp:
            return
        total = int(stamp.get("total_refused") or 0)
        lines.extend(["## Scope enforcement", ""])
        if not total:
            lines.extend(
                [
                    "No out-of-scope target was reached for. Every request this "
                    "engagement made was inside the authorised scope.",
                    "",
                ]
            )
            return
        hosts = stamp.get("out_of_scope_hosts") or {}
        lines.extend(
            [
                f"{total} attempt(s) to reach a target outside the authorised scope were "
                f"**refused**, across {len(hosts)} host(s). Nothing was sent to any of "
                f"them. These are links the target's own pages point at; following one "
                f"would mean testing a third party who authorised nothing.",
                "",
                "| Out-of-scope host | Attempts refused |",
                "| --- | ---: |",
            ]
        )
        for host, count in hosts.items():
            lines.append(f"| {host} | {count} |")
        lines.append("")
        if stamp.get("truncated"):
            lines.extend(
                [
                    f"The per-URL list below retains the first "
                    f"{stamp.get('retained')} of {total}; the counts above are exact.",
                    "",
                ]
            )

    @staticmethod
    def _render_plan_coverage(lines: list[str], report: PentestReport) -> None:
        """Render what the exploit plan's task cap dropped, and in what order.

        The plan cap is the bound that most directly decides what gets tested:
        candidate ``(class, endpoint)`` pairs are ranked and everything past the
        cap is dropped. It has been loud in the run log and the trace since four
        D1 baseline runs each truncated ~1,500 candidates to 150 in silence —
        and neither a log line nor ``trace.jsonl`` is something a client reads.
        Without this section a deliverable can say "we tested the target" over a
        plan that dropped the one endpoint a class could have confirmed on.

        Two facts, rendered apart because they have different fixes:

        * **Truncation** is the budget working. A larger cap
          (``EXPLOIT_MAX_PLAN_TASKS``) covers more.
        * A **ranking inversion** is the ordering failing: a task dropped from
          an endpoint carrying that class's own observed surface while
          lower-relevance tasks survived. A larger cap does not fix it, and it
          is what cost D1 its weak-session and SQLi findings. It reads nothing
          like tail truncation and must not be summed into it.

        Rendered when the plan fit too — "no class was truncated" is a claim,
        and a section that appears only on truncation cannot be told apart from
        one nobody wrote.
        """
        stamp = report.plan_coverage
        if not stamp or not stamp.get("passes_recorded"):
            return
        lines.extend(["## Plan coverage", ""])
        if not stamp.get("plan_truncated"):
            lines.extend(
                [
                    "Every candidate test the planner produced was dispatched — the plan "
                    "fit inside its task cap, so no class was truncated and the coverage "
                    "below is the whole plan.",
                    "",
                ]
            )
            return

        dropped_total = int(stamp.get("dropped_total") or 0)
        classes = list(stamp.get("classes_truncated") or [])
        inversions = int(stamp.get("ranking_inversion_count") or 0)
        lines.extend(
            [
                f"The task cap dropped **{dropped_total} candidate test(s)** across "
                f"{len(classes)} class(es). Those endpoints were identified and not "
                f"tested; nothing below reflects on them either way.",
                "",
                "| Class | Candidates dropped | First endpoint omitted |",
                "| --- | ---: | --- |",
            ]
        )
        for one_pass in stamp.get("passes") or []:
            if not isinstance(one_pass, dict):
                continue
            for name, endpoints in (one_pass.get("dropped_by_class") or {}).items():
                first = endpoints[0] if endpoints else "-"
                lines.append(f"| `{name}` | {len(endpoints)} | {first} |")
        lines.append("")

        if not inversions:
            lines.extend(
                [
                    "The ordering held: every dropped task ranked below the ones kept on "
                    "the signals its own class attacks. Raising the task cap is what "
                    "covers them.",
                    "",
                ]
            )
            return

        lines.extend(
            [
                f"**Ranking failure — {inversions} dropped task(s) should not have been.** "
                "Each sat on an endpoint where that class's own attack surface was "
                "observed, while lower-relevance tasks were kept. This is an ordering "
                "defect in the planner, not a budget one: raising the cap is not the "
                "fix, and the endpoints below were the ones most likely to confirm.",
                "",
                "| Class | Endpoint | Relevance grade |",
                "| --- | --- | ---: |",
            ]
        )
        for one_pass in stamp.get("passes") or []:
            if not isinstance(one_pass, dict):
                continue
            for inversion in one_pass.get("ranking_inversions") or []:
                if not isinstance(inversion, dict):
                    continue
                lines.append(
                    f"| `{inversion.get('test_method', '?')}` | "
                    f"{inversion.get('endpoint_url', '?')} | {inversion.get('grade', '?')} |"
                )
        lines.append("")

    @staticmethod
    def _render_research_grounding(lines: list[str], report: PentestReport) -> None:
        """State what the research behind this report actually read.

        A grounded research call reads today's advisories. An ungrounded one
        recites a training corpus, so **every vulnerability disclosed after that
        model's cutoff is invisible to it** — and, crucially, the answer carries
        no signal that anything is missing. A CVE list that looks complete and
        stops eighteen months ago is worse than no CVE list, because a reader
        cannot tell the two apart.

        Routing v2 is what made this reachable. Research led with Gemini
        Flash-Lite precisely for native Search Grounding; the Anthropic path
        that is now priority 1 has no equivalent, so the capability was traded
        away with the routing. This section is the disclosure of that trade on
        the run that took it, not a promise to restore it.

        Rendered whichever way it went — "this research read the live web" is a
        claim the deliverable should make explicitly, and a caveat that appears
        only when things went badly cannot be told apart from one nobody wrote.
        """
        stamp = report.research_grounding
        if not stamp:
            return
        lines.extend(["## Research grounding", ""])
        entries = int(stamp.get("runbook_entries") or 0)
        providers = ", ".join(str(p) for p in (stamp.get("providers") or [])) or "none"
        if stamp.get("is_grounded"):
            lines.extend(
                [
                    f"The research behind this report was **grounded in live web search** "
                    f"(served by: {providers}). Its {entries} runbook entr(ies) reflect "
                    f"advisories available at the time of testing.",
                    "",
                ]
            )
            return

        grounding = str(stamp.get("grounding") or "undeclared")
        why = {
            "training_data": (
                "the provider that served the research calls has no live-search "
                "capability on this path, so the answers came from its training corpus"
            ),
            "undeclared": (
                "the provider that served the research calls did not declare what its "
                "answers are grounded in, which is treated the same as ungrounded"
            ),
        }.get(grounding, "the grounding could not be established")

        lines.extend(
            [
                f"**This research was NOT grounded in live web search** "
                f"(`{grounding}`; served by: {providers}).",
                "",
                f"Why: {why}.",
                "",
                f"What this means for the {entries} runbook entr(ies) and any CVE named "
                "in them: they are bounded by the serving model's training cutoff. A "
                "vulnerability disclosed after that date is invisible here, and the "
                "research text gives no indication that anything is missing — so an "
                "apparently complete CVE list may simply stop. Treat the research half "
                "of this engagement as a starting point requiring an independent, "
                "current advisory check.",
                "",
                "This does not affect the findings above. Every finding in this report "
                "was confirmed by this engine's own oracles against the live target; a "
                "CVE from research is a LEAD that must reach one of those oracles before "
                "it can become a finding, and none of them consults the research text.",
                "",
            ]
        )

    @staticmethod
    def _render_llm_spend(lines: list[str], report: PentestReport) -> None:
        """Render what the run consumed and the caps it ran under."""
        stamp = report.llm_spend
        if not stamp or not stamp.get("total_tokens"):
            return
        token_cap = stamp.get("token_cap")
        usd_cap = stamp.get("usd_cap")
        lines.extend(["## LLM consumption", ""])
        caps = []
        caps.append(f"token cap {int(token_cap):,}" if token_cap else "no token cap")
        caps.append(f"spend cap ${float(usd_cap):.2f}" if usd_cap else "no spend cap")
        lines.extend(
            [
                f"Ran under: {', '.join(caps)}.",
                "",
                f"- Input tokens: {int(stamp.get('input_tokens') or 0):,}",
                f"- Output tokens: {int(stamp.get('output_tokens') or 0):,}",
                f"- Total tokens: {int(stamp.get('total_tokens') or 0):,}",
            ]
        )
        if stamp.get("usd_is_complete"):
            lines.append(f"- Cost: ${float(stamp.get('usd_spent') or 0.0):.4f}")
        else:
            unpriced = ", ".join(stamp.get("unpriced_models") or [])
            lines.append(
                f"- Cost: ${float(stamp.get('usd_spent') or 0.0):.4f} "
                f"(**lower bound** — no rate declared for: {unpriced})"
            )
        lines.append("")

    @staticmethod
    def _render_provider_degradation(lines: list[str], report: PentestReport) -> None:
        """Render which model actually served each call, when it was not the primary.

        Sits beside *Component contribution* and answers the neighbouring
        question. That section says which components produced nothing; this one
        says whether the answers that WERE produced came from the model this
        run asked for.

        Always rendered, clean or not. The previous behaviour was to render
        nothing, and that is exactly how six exploit plans and six
        false-positive cross-checks written by the cheap tier reached six
        reports that looked like reports it had not happened to.
        """
        stamp = report.provider_degradation
        if not stamp:
            return
        lines.extend(["## Provider routing", ""])
        if not stamp.get("provider_degraded"):
            lines.extend(
                [
                    "Every LLM call was served by the provider this run asked for. "
                    "No fallback activated, so the run is eligible for use as a "
                    "baseline.",
                    "",
                ]
            )
            return

        events = [e for e in (stamp.get("events") or []) if isinstance(e, dict)]
        decision_bearing = int(stamp.get("decision_bearing_fallback_count") or 0)
        lines.extend(
            [
                f"**This run is NOT eligible as a baseline.** {stamp.get('fallback_count', 0)} "
                f"call(s) were served by a provider other than the one asked for. A "
                f"number produced partly by one model and partly by another is not a "
                f"measurement of the target, so nothing here should be compared against "
                f"another run's figures.",
                "",
            ]
        )
        if decision_bearing:
            lines.extend(
                [
                    f"{decision_bearing} of them were **decision-bearing** — the exploit "
                    "plan decides what gets tested and the false-positive cross-check "
                    "decides which findings survive, so those are not only a "
                    "comparability problem.",
                    "",
                ]
            )
        lines.extend(
            [
                "| Call site | Asked for | Served by | Why | Decision-bearing |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for event in events:
            asked = f"{event.get('asked_provider', '')}/{event.get('asked_model', '')}"
            served = f"{event.get('served_provider', '')}/{event.get('served_model', '')}"
            lines.append(
                f"| {event.get('call_site', '')} | {asked} | {served} | "
                f"{event.get('reason', '') or '-'} | "
                f"{'yes' if event.get('decision_bearing') else 'no'} |"
            )
        lines.append("")

    @staticmethod
    def _render_component_ledger(lines: list[str], report: PentestReport) -> None:
        """Render the components that contributed nothing, and who covered.

        Sits next to *What was NOT tested* and answers the neighbouring
        question. That section says which classes were never attempted; this one
        says which components ran and produced nothing — a distinction a reader
        cannot otherwise make, because a component that contributes zero looks
        exactly like a target that had nothing to find.

        Silent when no ledger was installed (a directly invoked ReportAgent), and
        silent when nothing alarmed — an all-clear line rather than a table.
        """
        ledger = report.component_ledger
        if not ledger:
            return
        alarms = ledger.get("alarms") or []
        summary = ledger.get("summary") or {}
        correctly_empty = [c for c in (ledger.get("correctly_empty") or []) if isinstance(c, dict)]
        lines.extend(["## Component contribution", ""])
        if not alarms:
            lines.extend(
                [
                    f"All {summary.get('components_tracked', 0)} tracked component(s) "
                    "contributed at least one item, or found nothing correctly. No "
                    "fallback covered for a component that produced nothing.",
                    "",
                ]
            )
        else:
            lines.extend(
                [
                    "The components below ran and contributed nothing, or were covered "
                    "for by a fallback. A finding total says nothing about which "
                    "components produced it, so they are named here.",
                    "",
                    "| Component | Kind | Invoked | Succeeded | Items | Alarm |",
                    "| --- | --- | ---: | ---: | ---: | --- |",
                ]
            )
            for rec in alarms:
                if not isinstance(rec, dict):
                    continue
                lines.append(
                    f"| {rec.get('component', '?')} | {rec.get('kind', '?')} | "
                    f"{rec.get('invocations', 0)} | {rec.get('successes', 0)} | "
                    f"{rec.get('items_contributed', 0)} | "
                    f"{', '.join(rec.get('alarms') or []) or '—'} |"
                )
            lines.append("")
            for fb in ledger.get("fallbacks") or []:
                if isinstance(fb, dict):
                    lines.append(
                        f"- Fallback: **{fb.get('covered_by', '?')}** covered for "
                        f"**{fb.get('component', '?')}** "
                        f"({fb.get('reason') or 'no reason recorded'})"
                    )
            lines.append("")

        if correctly_empty:
            # Deliberately NOT in the table above. These ran, produced nothing,
            # and were right to — a GraphQL reader on an application with no
            # GraphQL. Listing them as alarms every run is how an alarm section
            # stops being read.
            lines.extend(
                [
                    "### Found nothing, correctly",
                    "",
                    "These components ran and produced nothing because the input "
                    "they read was not present on this target — not because they "
                    "failed. Each states what it examined, so the claim is "
                    "checkable rather than self-assessed.",
                    "",
                ]
            )
            for rec in correctly_empty:
                reasons = "; ".join(str(r) for r in (rec.get("reasons") or []))
                lines.append(
                    f"- **{rec.get('component', '?')}** — {reasons or 'precondition absent'}"
                )
            lines.append("")

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

            # The benchmark declaration, rendered as prominently as the
            # authorization it lives on. A run in which destructive categories
            # were permitted is a materially different run, and a reader must not
            # have to infer that from an action-log count.
            if record.benchmark_profile is not None:
                lines.extend(["> **" + record.benchmark_profile.header_lines()[0] + "**", ""])
                lines.extend([f"- {line}" for line in record.benchmark_profile.header_lines()[1:]])
                lines.extend(
                    [
                        "",
                        "> Every request this permitted is in the action log, tagged with "
                        "the category that would otherwise have refused it "
                        "(`clinkz actions <engagement-id>`).",
                        "",
                    ]
                )

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
                lines.extend(ReportAgent._render_session_maintenance(auth))
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
    def _render_session_maintenance(auth: dict[str, Any]) -> list[str]:
        """Render session maintenance so the numbers explain themselves.

        A client reading "15 loss signals, 0 re-authentications" cannot tell
        whether the tool spent the engagement in a broken session or whether the
        signals were never evidence of anything. A run once printed exactly that
        line, and the truth was the second: every signal came from the engine's
        own anonymous controls. Each number now says what it counted, and a
        flagged check that ended without a re-login is named as the verified
        false alarm it was rather than left looking like an unhandled failure.
        """
        losses = int(auth.get("session_losses_detected") or 0)
        ignored = int(auth.get("control_responses_ignored") or 0)
        pre_session = int(auth.get("pre_session_signals") or 0)
        checks = int(auth.get("session_checks_performed") or 0)
        false_alarms = int(auth.get("session_false_alarms") or 0)
        reauths = int(auth.get("reauthentications") or 0)
        if not (losses or ignored or pre_session or checks or reauths):
            return []

        detail = [
            f"{losses} unauthenticated response(s) to session-bearing requests",
            f"{checks} session verification(s)",
            f"{reauths} re-authentication(s) performed",
        ]
        lines = [f"- **Session maintenance:** {'; '.join(detail)}."]
        if false_alarms:
            lines.append(
                f"  - {false_alarms} flagged check(s) re-proved the session was still "
                "authenticated; no re-login was needed."
            )
        if ignored:
            lines.append(
                f"  - {ignored} unauthenticated response(s) came from deliberately "
                "session-free requests (anonymous controls and login-endpoint "
                "detection) and are not evidence of session loss."
            )
        if pre_session:
            lines.append(
                f"  - {pre_session} unauthenticated response(s) preceded the first "
                "established session (login and mechanism-detection traffic) and are "
                "not evidence of session loss either."
            )
        if checks > reauths + false_alarms:
            lines.append(
                f"  - {checks - reauths - false_alarms} check(s) could not be resolved — "
                "no usable credential, or re-authentication failed. Coverage after "
                "that point may be unauthenticated."
            )
        return lines

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
            NotTestedCategory.SOURCE_NOT_INGESTED: ("Gray-box source supplied but not analysed"),
            NotTestedCategory.OUT_OF_SCOPE: "Excluded by the client",
            NotTestedCategory.NOT_PERMITTED: "Techniques not authorized",
            NotTestedCategory.NO_CLIENT_SIDE_ORACLE: ("Not confirmable — no client-side oracle"),
            NotTestedCategory.NOT_IMPLEMENTED: "Not confirmable — no methodology",
            NotTestedCategory.DESTRUCTIVE_REFUSED: ("Refused by the production safety rails"),
            NotTestedCategory.ENGAGEMENT_HALTED: "Cut short when the engagement halted",
            NotTestedCategory.UNAUTHENTICATED: "Limited by the sessions available",
        }
        rendered: set[str] = set()
        for category, heading in headings.items():
            group = [item for item in report.not_tested if item.category == category]
            if not group:
                continue
            rendered.add(str(category))
            lines.extend([f"### {heading}", ""])
            for item in group:
                lines.append(f"- **{item.item}** — {item.reason}")
            lines.append("")

        # A category with no heading is rendered anyway, under its raw name. The
        # section exists to say what was NOT tested; dropping an entry because a
        # renderer was not updated alongside the enum would delete a limitation
        # from a client deliverable — the one failure this section cannot have.
        orphans = [item for item in report.not_tested if str(item.category) not in rendered]
        if orphans:
            lines.extend(["### Other limitations", ""])
            for item in orphans:
                lines.append(f"- **{item.item}** [{item.category}] — {item.reason}")
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

    @staticmethod
    def _render_chains(lines: list[str], chains: list[dict[str, object]]) -> None:
        """Render the link-by-link view of every CONFIRMED chain.

        The chains are already in the findings section — each was emitted through
        the same chokepoint as every other finding — so this section adds no
        count and no claim. What it adds is the composition: which step produced
        what, which oracle proved each link, and the decoy the carriage was
        distinguished against. A chain finding's severity is an escalation, and a
        reader is entitled to check the escalation against the links it rests on.
        """
        if not chains:
            return
        lines.extend(
            [
                "## Confirmed attack chains — composition detail",
                "",
                "> Each chain below is **already counted once** in the findings section; "
                "this is the link-by-link view. A chain is confirmed only when every "
                "link was independently confirmed by one of this engine's oracles AND "
                "the carried artifact was accepted while an equivalently-shaped decoy "
                "was refused. The severity is escalated from what the chain "
                "DEMONSTRATED, never from what the composition could in principle lead "
                "to.",
                "",
            ]
        )
        for i, chain in enumerate(chains, 1):
            links = chain.get("links") or []
            lines.extend(
                [
                    f"### C{i}. {chain.get('chain_kind', 'chain')}",
                    "",
                    f"- **Severity:** {str(chain.get('severity', '')).upper()} "
                    f"(escalated from {chain.get('base_severity', '')})",
                    f"- **Composed grade (weakest link):** {chain.get('composed_grade', '')}",
                    f"- **Demonstrated impact:** {chain.get('impact_statement', '')}",
                    "",
                    "**Links:**",
                    "",
                ]
            )
            for link in links if isinstance(links, list) else []:
                if not isinstance(link, dict):
                    continue
                lines.append(
                    f"{link.get('ordinal', '?')}. `{link.get('kind', '')}` "
                    f"**{link.get('test_method', '')}** on {link.get('endpoint', '')} "
                    f"— confirmed by {link.get('confirmation_primitive', 'n/a')} "
                    f"— {link.get('description', '')}"
                )
                composition = link.get("composition")
                if isinstance(composition, dict):
                    lines.extend(
                        [
                            "",
                            "   **Decoy control:**",
                            "   ```",
                            f"   carried:   {composition.get('carried_kind', '')} "
                            f"(fingerprint {composition.get('carried_fingerprint', '')})",
                            f"   decoy:     fingerprint "
                            f"{composition.get('decoy_fingerprint', '')} — "
                            f"{composition.get('decoy_shape', '')}",
                            f"   signal:    {composition.get('acceptance_signal', '')}",
                            f"   real:      status={composition.get('real_status')} "
                            f"accepted={composition.get('real_accepted')}",
                            f"   decoy:     status={composition.get('decoy_status')} "
                            f"accepted={composition.get('decoy_accepted')}",
                            "   ```",
                        ]
                    )
            lines.extend(["", "---", ""])

    @staticmethod
    def _render_chain_leads(lines: list[str], leads: list[ChainResearchLead]) -> None:
        """Render the dedicated 'Unproven attack chains (UNCONFIRMED)' section.

        Third lead type, third separate section, same hard line. This one is the
        most important of the three to keep separate: two confirmed findings sit
        next to each other in a result list and a narrative connecting them writes
        itself, so a composition that could not be proven has to be visibly a
        composition that could not be proven. Each lead names the exact link that
        stopped it, which is what makes it worth an operator's time rather than a
        shrug.
        """
        if not leads:
            return
        lines.extend(
            [
                "## Unproven attack chains (candidate compositions — UNCONFIRMED)",
                "",
                "> These compositions were worth trying and were **not proven**. They are "
                "**NOT findings**, are **not counted** in the totals above, and no "
                "escalated impact is claimed. Most often the carried artifact was "
                "accepted but so was an equivalently-shaped decoy the target never "
                "issued — which means the endpoint accepts the SHAPE rather than the "
                "value, so its acceptance says nothing about what was recovered.",
                "",
            ]
        )
        for i, lead in enumerate(leads, 1):
            lines.extend(
                [
                    f"### X{i}. {lead.candidate_chain}",
                    "",
                    f"- **Why unconfirmed:** {lead.why_unconfirmed}",
                    f"- **Link that stopped it:** {lead.unconfirmed_link}",
                    f"- **Carried artifact:** {lead.carried_artifact_kind} "
                    f"(fingerprint {lead.carried_artifact_fingerprint})",
                    "",
                    "**Links:**",
                    "",
                    *[f"- {line}" for line in lead.links],
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
