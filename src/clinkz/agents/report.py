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
from clinkz.agents._report_integrity import (
    TestingWindowError,
    authentication_state,
    authentication_verdict,
    reconcile_reachability_claims,
    reconciled_not_tested_reason,
    spend_cost_line,
    testing_window,
)
from clinkz.engagement.secrets import redact, redact_structure
from clinkz.knowledge.component_cves import (
    BAND_C_VECTORS,
    CARRIABLE_VECTORS,
    KNOWN_COMPONENT_CVES,
)
from clinkz.llm.base import LLMClient
from clinkz.llm.degradation import (
    degradation_summary,
    exhausted_stages,
    reconcile_with_model_stamp,
)
from clinkz.llm.spend import spend_summary
from clinkz.models.engagement import AuthorizationRecord, EngagementWindow
from clinkz.models.finding import (
    ChainResearchLead,
    CrossServiceResearchLead,
    Finding,
    FindingStatus,
    ResidualMutation,
    Severity,
    UnprovenExploitLead,
)
from clinkz.models.recon import DetectedComponent, inventory_summary
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
from clinkz.observability.plan_alarms import crawl_budget_summary, plan_alarm_summary
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


#: Phase result statuses that mean the phase did not produce its output. The
#: orchestrator writes ``{"status": "error", ...}`` on an ERROR message and on a
#: force-kill; ``"stopped"`` is an agent that ended itself early.
_FAILED_PHASE_STATUSES: frozenset[str] = frozenset({"error", "failed"})

#: A phase the orchestrator force-killed at its own wall clock. Held APART from
#: the failures above, because the two are different facts about a run and a
#: reader acts on them differently: a failure is the phase breaking, a timeout is
#: a bound the operator configured being reached, which is a coverage statement
#: of the same kind as the plan cap and the crawl budget.
#:
#: Whether it also makes the run INCOMPLETE is decided by what the phase handed
#: over, not by which phase it was. ``_phase_stop_result`` carries through
#: whatever the agent already delivered, so a timeout WITH a result is a phase
#: that did its work and ran out of clock; a timeout with NOTHING is
#: indistinguishable from a phase that never ran, and that is the shape the
#: banner exists to catch. Deciding it on an engine fact rather than on a list of
#: which phases matter is deliberate: a hand-maintained list of exempt phases
#: would be another guard domain to keep in sync, and the member it forgot would
#: be the one that needed it.
_TIMEOUT_PHASE_STATUS = "timeout"


def _run_completion(
    *,
    phase_outcomes: dict[str, Any],
    model_stamp: list[dict[str, Any]],
) -> tuple[bool, str]:
    """Whether this run completed, and the sentence that says why not.

    Two independent witnesses, because neither is available in both situations.
    ``phase_outcomes`` is what the orchestrator observed and is authoritative
    live; ``model_stamp`` is written from the run's own trace and is the only
    one that survives into a stored bundle, where the process that knew the
    phase statuses ended long ago.

    A run that failed a phase and rendered "0 findings identified. Risk rating:
    Informational." made the strongest claim a pentest report contains — this
    target is clean — out of no evidence at all. Engagement ``2e21a200`` failed
    recon, scan AND exploit and said exactly that.

    **A TIMEOUT is graded on what the phase delivered, not on which phase it
    was.** Folding ``"timeout"`` in with ``"error"`` made the banner flip between
    runs that were otherwise the same: across three identical Juice Shop
    envelope runs the research phase overran its grace window once, and that one
    report carried "THIS RUN DID NOT COMPLETE" over the same findings the other
    two rendered clean. The banner exists so a bad run cannot hide, and a claim
    that fires on a third of good runs is one a reader learns to skip. So a
    timeout that carried a result is a completed phase that ran out of clock;
    only a timeout that delivered NOTHING still trips the banner, because a
    phase that handed nothing over cannot be told apart from one that never
    ran.

    Args:
        phase_outcomes: ``{phase_name: result_dict}`` from the orchestrator.
        model_stamp: The run's own ``model_stamp`` rows.

    Returns:
        ``(run_completed, incomplete_reason)``. The reason is empty when the run
        completed.
    """
    failed = sorted(
        name
        for name, result in phase_outcomes.items()
        if isinstance(result, dict)
        and str(result.get("status", "")).lower() in _FAILED_PHASE_STATUSES
    )
    # A timeout that delivered nothing is a phase that produced no work, which is
    # what "did not complete" means. A timeout that delivered a result is not:
    # the phase handed its work over and was then stopped at a configured bound.
    timed_out_empty = sorted(
        name
        for name, result in phase_outcomes.items()
        if isinstance(result, dict)
        and str(result.get("status", "")).lower() == _TIMEOUT_PHASE_STATUS
        and not result.get("result")
    )
    starved = exhausted_stages(model_stamp)
    if not failed and not timed_out_empty and not starved:
        return True, ""
    parts: list[str] = []
    if failed:
        parts.append(
            f"The {', '.join(failed)} phase{'s' if len(failed) > 1 else ''} did not complete."
        )
    if timed_out_empty:
        plural = "s" if len(timed_out_empty) > 1 else ""
        verb = "were" if len(timed_out_empty) > 1 else "was"
        parts.append(
            f"The {', '.join(timed_out_empty)} phase{plural} {verb} stopped at the "
            f"engagement's wall clock before delivering any result, so nothing from "
            f"{'them' if len(timed_out_empty) > 1 else 'it'} reached this report."
        )
    if starved:
        parts.append(
            f"No LLM provider served the {', '.join(starved)} "
            f"stage{'s' if len(starved) > 1 else ''}: the whole chain was exhausted, so "
            f"that reasoning step produced nothing and the phase continued without it."
        )
    return False, " ".join(parts)


def write_report_pdf(report: PentestReport, path: Path) -> Path | None:
    """Write the PDF deliverable, or log loudly and return ``None``.

    Tolerant HERE and nowhere else. ``clinkz report-pdf`` lets the exception out,
    because an operator who asked for the document must be told the renderer is
    missing rather than handed a zero-byte success. Inside a live engagement the
    opposite is true: the findings are already on disk in two other formats, and
    losing them to a layout error in a third would be a worse trade than losing
    the third.

    It is not silent either way — a missing PDF is logged at ERROR with the
    exception type, so "the deliverable did not appear" is never something an
    operator has to infer from an empty directory.

    Args:
        report: The already-redacted report.
        path: Destination.

    Returns:
        The path written, or ``None`` when the renderer was unavailable or
        failed.
    """
    try:
        from clinkz.agents._report_pdf import ControlArmRuleMissingError, render_report_pdf
    except ImportError as exc:  # pragma: no cover — reportlab is a declared dep
        from clinkz.agents._report_pdf import PDF_UNAVAILABLE_HINT

        logger.error("%s (%s)", PDF_UNAVAILABLE_HINT, exc)
        return None
    try:
        return render_report_pdf(report, path)
    except ImportError as exc:
        from clinkz.agents._report_pdf import PDF_UNAVAILABLE_HINT

        logger.error("%s (%s)", PDF_UNAVAILABLE_HINT, exc)
        return None
    except (ControlArmRuleMissingError, TestingWindowError) as exc:
        # Caught by NAME, ahead of the broad handler, because these two messages
        # are OURS. The generic branch below withholds the message for a good
        # reason — ReportLab quotes the target's bytes back — and that reason is
        # false here: both are composed entirely of engine-declared facts, and
        # they are exactly the diagnosis an operator needs. A refusal nobody can
        # read is a refusal that gets worked around.
        logger.error("PDF deliverable NOT written - the document would misstate itself: %s", exc)
        return None
    except Exception as exc:  # noqa: BLE001 — a layout error must not lose the findings
        # The TYPE is logged and the MESSAGE is not, for the same reason the
        # disclosure gate withholds pypdf's: ReportLab's paragraph parser quotes
        # the offending markup back in its error text, and the markup here is
        # built out of a finding's evidence — raw request and response bytes
        # from the host under test. Logging is not a redaction chokepoint, so a
        # layout error would copy exactly the material every writer in this
        # repository redacts into the run log. An exception class name is our
        # vocabulary; its message is the target's.
        logger.error(
            "PDF deliverable NOT written (%s; message withheld: a layout error quotes the "
            "evidence that caused it). The JSON and Markdown reports are unaffected; "
            "regenerate the PDF with `clinkz report-pdf <engagement-id>` once the cause "
            "is fixed.",
            type(exc).__name__,
        )
        return None


def _parse_authorization(raw: Any) -> AuthorizationRecord | None:
    """Rebuild the authorization record from the orchestrator's handoff dict."""
    if not isinstance(raw, dict):
        return None
    try:
        return AuthorizationRecord.model_validate(raw)
    except Exception as exc:  # noqa: BLE001 — a bad header must not lose the findings
        logger.warning("Could not parse the authorization record for the report: %s", exc)
        return None


def _parse_residual_mutations(raw: Any) -> list[ResidualMutation]:
    """Rebuild the residual-mutation records from the orchestrator's handoff.

    A malformed entry is DROPPED with a warning rather than taking the section
    down, for the same reason a bad authorization header does not lose the
    findings — but each drop is logged loudly, because the thing being dropped
    is a change we made to the client's running process and silence about it is
    the failure this section exists to prevent.
    """
    mutations: list[ResidualMutation] = []
    for entry in raw or []:
        if not isinstance(entry, dict):
            continue
        try:
            mutations.append(ResidualMutation.model_validate(entry))
        except Exception as exc:  # noqa: BLE001 — one bad row must not lose the rest
            logger.warning(
                "Could not parse a residual-mutation record for the report — a change "
                "this run made to the target will be missing from the deliverable: %s",
                exc,
            )
    return mutations


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

        # Whether the run got to the end. Read BEFORE the summary is built,
        # because it changes what the summary is allowed to claim: on an
        # incomplete run "0 findings. Risk rating: Informational" states that
        # the target is clean on the strength of testing that did not happen.
        model_stamp = _active_model_stamp()
        run_completed, incomplete_reason = _run_completion(
            phase_outcomes=dict(input_data.get("phase_outcomes") or {}),
            model_stamp=model_stamp,
        )
        if not run_completed:
            self._logger.warning(
                "Report: this run did NOT complete — %s The executive summary will say so "
                "and the counts are rendered as a floor.",
                incomplete_reason,
            )
            if not finding_models:
                # "Informational" is a verdict about the target. With no
                # findings AND no completed run there is nothing to have a
                # verdict about, and the honest rating is that none was reached.
                risk_rating = "Not assessed"

        overview = (
            f"Penetration test of {', '.join(scope_values)}. "
            f"{len(finding_models)} findings identified."
        )
        if not run_completed:
            overview = (
                f"Penetration test of {', '.join(scope_values)}. "
                f"THIS RUN DID NOT COMPLETE. {incomplete_reason} "
                f"{len(finding_models)} finding(s) were identified by the part of the "
                f"engagement that ran; that is a floor on what is present, not a "
                f"measurement of the target."
            )

        exec_summary = ExecutiveSummary(
            overview=overview,
            risk_rating=risk_rating,
            critical_count=severity_counts[Severity.CRITICAL],
            high_count=severity_counts[Severity.HIGH],
            medium_count=severity_counts[Severity.MEDIUM],
            low_count=severity_counts[Severity.LOW],
            info_count=severity_counts[Severity.INFO],
            run_completed=run_completed,
            incomplete_reason=incomplete_reason,
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
            # What testing left behind that the client has to clear themselves.
            # Handed in by the orchestrator from the exploit result and rendered
            # verbatim; nothing here decides whether a mutation happened, which
            # is the methodology's own witnessed observation.
            residual_mutations=_parse_residual_mutations(input_data.get("residual_mutations")),
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
                finding_count=len(finding_models),
                graybox_source=dict(input_data.get("graybox_source") or {}),
                resumed_from=str(input_data.get("resumed_from") or ""),
                client_oracle=dict(input_data.get("client_oracle") or {}),
            ),
            safety_summary=safety,
            authentication=authentication,
            # Reconciled against this run's own completion banner, at the BUILD
            # seam so report.json carries it. ``unreachable`` renders a sentence
            # per component about what this target does not expose, and a run
            # that did not complete did not observe that.
            component_ledger=reconcile_reachability_claims(
                _active_ledger_snapshot(),
                run_completed=run_completed,
                incomplete_reason=incomplete_reason,
            ),
            model_stamp=model_stamp,
            # Reconciled against the run's OWN model stamp, not taken from the
            # register alone. The two witnessed one fact and disagreed: the
            # stamp recorded ``provider: "exhausted"`` for three phases while
            # the register — which only ever saw substitutions — reported
            # ``provider_degraded: false``. Reconciling HERE puts the honest
            # verdict in ``report.json``, so the JSON, Markdown and PDF cannot
            # disagree about it either.
            provider_degradation=reconcile_with_model_stamp(degradation_summary(), model_stamp),
            scope_refusals=scope_refusal_summary(),
            llm_spend=spend_summary(),
            plan_coverage=plan_alarm_summary(),
            crawl_coverage=crawl_budget_summary(),
            # What this run OBSERVED, with the provenance of every version.
            # Built here from recon's own rows rather than from
            # ``hosts[].services``, which has been empty on every bundle ever
            # written — so the inventory that decides which known-CVE match
            # claims a reserved plan slot has never once reached a deliverable.
            component_inventory=inventory_summary(
                self._parse_components(input_data.get("components"))
            ),
            research_grounding=dict(input_data.get("research_grounding") or {}),
        )

        # The report is the artifact that actually reaches the client, so it
        # goes through the same redaction chokepoint as the trace and the
        # invocation records rather than being written raw. It used to be
        # written raw: every OTHER writer redacted, and the one document
        # designed to be handed over did not.
        report_dict = redact_structure(report.model_dump(mode="json"))

        # Both documents now render from the SAME redacted structure.
        #
        # They did not, and Markdown was the weaker path of the two. JSON was
        # built from `report_dict` above — `redact_structure` is KEY-AWARE, so a
        # `Set-Cookie` value is removed on the strength of its key, which is the
        # only thing identifying it: the target chose the value, so it has no
        # intrinsic shape for a string rule to match. Markdown was rendered from
        # the UNREDACTED `report` and scrubbed afterwards with `redact()`, a
        # pure string pass. By then the header dict has been flattened into
        # prose and the key is gone, so exactly the material key-awareness
        # exists to catch survived into the document a client actually reads.
        #
        # Round-tripping the redacted dict back through the model is what closes
        # it: the renderer cannot reach a value the structure no longer holds.
        # Deliberately not wrapped in a `try` — if redaction produced something
        # this model rejects, that is a defect in redaction, and a fallback to
        # the old path would silently restore the weaker document under the same
        # filename. No field here is more constrained than `str`, so a
        # `[REDACTED]` substitution cannot invalidate one.
        redacted_report = PentestReport.model_validate(report_dict)

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
            # `redact()` stays as a second pass over the rendered text: the
            # structural pass cannot see a value the RENDERER composes out of
            # two fields, and it costs nothing to keep both.
            redact(self._render_markdown(redacted_report, redacted_report.findings)),
            encoding="utf-8",
        )
        self._logger.info("Markdown report written to %s", md_path)

        # Write the PDF deliverable — the THIRD renderer of the same redacted
        # structure, never of the live report. It is the document that actually
        # reaches a client, so it must not be the one built from a different
        # source than the two that are grep-able.
        pdf_path = write_report_pdf(redacted_report, output_dir / f"report_{engagement_id}.pdf")
        if pdf_path:
            self._logger.info("PDF report written to %s", pdf_path)

        self._logger.info(
            "Report complete: %d findings, risk_rating=%s",
            len(report.findings),
            risk_rating,
        )

        return {
            "report": report_dict,
            "json_path": str(json_path),
            "markdown_path": str(md_path),
            "pdf_path": str(pdf_path) if pdf_path else "",
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
        finding_count: int,
        graybox_source: dict[str, Any] | None = None,
        resumed_from: str = "",
        client_oracle: dict[str, Any] | None = None,
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
            finding_count: Confirmed findings this run emitted, so the
                authenticated-surface item can be reconciled against them rather
                than written off one boolean.
            graybox_source: What happened to the ``--source`` tree, when one was
                supplied. Empty on a black-box engagement.
            resumed_from: The engagement this deliverable was regenerated from,
                when ``clinkz scan --resume`` produced it.
            client_oracle: What the P7 client-side execution oracle did — whether
                one was resolved, how many times it ran, how many of those
                witnessed execution. Empty when the exploit phase reported
                nothing, which is read as "no oracle" (the conservative reading:
                a run that cannot say what it did did not demonstrate it did
                anything).

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
        elif authorization is not None:
            # A wildcard authorizes every class EXCEPT the ones whose effect
            # outlives the run, and the client has to be told which those were
            # rather than left to assume a blanket yes covered them. "Test
            # everything" is not "leave my process altered until I restart it",
            # and the class the dispatcher withheld on that reasoning is
            # invisible in a deliverable that lists only explicit exclusions.
            from clinkz.agents.exploit import TERMINAL_DISPATCH_CLASSES

            for vuln_class in VULN_CLASSES:
                if vuln_class.test_method not in TERMINAL_DISPATCH_CLASSES:
                    continue
                items.append(
                    NotTestedItem(
                        item=vuln_class.label,
                        category=NotTestedCategory.NOT_PERMITTED,
                        reason=(
                            "This class leaves the target altered in a way the application "
                            "cannot undo — proving it requires restarting the affected "
                            "process afterwards — "
                            f"{TERMINAL_DISPATCH_CLASSES[vuln_class.test_method]}. "
                            "A blanket authorization does not cover that, so it was not "
                            f"attempted. To include it, name '{vuln_class.key}' explicitly "
                            "in the permitted-technique list."
                        ),
                    )
                )

        # Classes whose defining effect happens in a browser. WHICH limitation
        # applies is a fact about this run, not about the class: an oracle that
        # was never resolved is an absent capability, and an oracle that ran and
        # witnessed nothing is an exercised one. Engagement ``d67835f5`` reported
        # the second as the first — three classes filed under "no client-side
        # oracle" while P7 executed 40 times, every run returning
        # ``executed=False`` with its never-injected control silent, i.e. the
        # oracle refusing seven DOM-XSS candidates exactly as designed. A client
        # reading that section was told the engine could not look, when it had
        # looked and found nothing.
        #
        # The claim is read off runs that REPORTED, not off runs that were
        # SPENT. A runner reply carrying no verdict used to validate into a
        # default verdict and count as a clean non-execution, which pushed this
        # section toward "the oracle looked and saw nothing" on the strength of
        # an attempt that observed nothing in either direction. ``reported`` is
        # absent from bundles written before that distinction existed, and the
        # ABSENCE of the key is what separates an older bundle from a newer one
        # — the same rule the testing window follows — so an older bundle falls
        # back to ``runs`` and renders exactly as it did before.
        oracle = client_oracle or {}
        oracle_runs = int(oracle.get("runs") or 0)
        reported = oracle.get("reported")
        oracle_reported = int(reported if reported is not None else oracle_runs)
        oracle_ran = bool(oracle.get("resolved")) and oracle_reported > 0
        witnessed = int(oracle.get("executions_witnessed") or 0)
        for vuln_class in VULN_CLASSES:
            if vuln_class.capability is not ConfirmationCapability.CLIENT_SIDE_ORACLE_REQUIRED:
                continue
            if oracle_ran:
                items.append(
                    NotTestedItem(
                        item=vuln_class.label,
                        category=NotTestedCategory.CLIENT_ORACLE_FOUND_NOTHING,
                        reason=(
                            f"The client-side execution oracle WAS available and ran "
                            f"{oracle_runs} time(s) this engagement, reporting a verdict "
                            f"on {oracle_reported} of them and witnessing execution "
                            f"{witnessed} time(s). Where a candidate of this class is not "
                            "among the confirmed findings, it is because the oracle "
                            "loaded the page in a real browser and no attacker-supplied "
                            "script ran — not because the engine was unable to look. "
                            "Candidates that reached the oracle and were refused are "
                            "recorded as unproven leads with the browser's own verdict."
                        ),
                    )
                )
            else:
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

        # Shapes a class refuses to confirm on even when the engagement gave it
        # everything it needs. The producer declares the boundary and the
        # registered abstain reason it produces
        # (:class:`~clinkz.models.vuln_classes.CoverageBoundary`); nothing here
        # decides what the boundary is.
        #
        # Rendered on a clean run too, like every other bound that decided
        # coverage. The IDOR one is why the category exists: an endpoint serving
        # per-user records that name no owner produces exactly the artifact a
        # sound endpoint produces — nothing — so leaving the boundary pinned in a
        # test and out of the deliverable lets an absence of findings read as an
        # absence of flaws, which is the silence every other rule in this section
        # exists to break.
        for vuln_class in VULN_CLASSES:
            if not vuln_class.coverage_boundary.declared:
                continue
            items.append(
                NotTestedItem(
                    item=f"{vuln_class.label} — records this class cannot attribute",
                    category=NotTestedCategory.CLASS_ABSTAINS,
                    reason=vuln_class.coverage_boundary.limitation,
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
        #
        # "Anything behind authentication was not examined" is the strongest
        # sentence in this section and it used to be written off one boolean.
        # 3c47a0de rendered it above 22 findings at /vulnerabilities/sqli/,
        # /exec/, /fi/ and /upload/ — every one of them behind DVWA's login,
        # reached on a session the default-credential sweep established and never
        # registered. The claim is now made only when the reconciliation says the
        # run can back it; otherwise the item states the inconsistency, which is a
        # different limitation with a different remedy.
        if not authentication.get("authenticated"):
            verdict = authentication_verdict(authentication, finding_count)
            items.append(
                NotTestedItem(
                    item="Authenticated application surface",
                    category=NotTestedCategory.UNAUTHENTICATED,
                    reason=(
                        (
                            "No authenticated session was established for this "
                            "engagement, so only the surface reachable without a login "
                            "was tested. Anything behind authentication was not examined."
                        )
                        if verdict.may_assert_no_session
                        else (
                            "This engagement's authentication record says no session was "
                            "established and the run's own output contradicts it, so the "
                            "authenticated surface can be reported neither as tested nor "
                            "as untested. " + " ".join(verdict.contradictions)
                        )
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
        summary = report.executive_summary
        if summary is not None and not summary.run_completed:
            # Ahead of the counts, not after them. A reader who takes the number
            # and stops has to have hit this first: on an incomplete run the
            # number bounds this engine's coverage, not the target's security.
            lines.extend(
                [
                    "> **THIS RUN DID NOT COMPLETE.** "
                    + (summary.incomplete_reason or "One or more phases failed.")
                    + " Every count below is a FLOOR over the part of the engagement that "
                    "ran. The absence of a finding here is not evidence that the target "
                    "is sound.",
                    "",
                ]
            )
        lines.extend(
            [
                "## Summary",
                "",
                f"- **Risk rating:** {summary.risk_rating if summary else 'N/A'}",
                f"- **Confirmed findings:** {len(findings)}",
                f"- **Confirmed attack chains:** {len(report.confirmed_chains)} "
                "(each is also one of the findings above, never counted twice)",
                f"- **Unconfirmed leads:** {unconfirmed} (not counted above)",
                "",
                "---",
                "",
            ]
        )
        # Before the findings, not after them. This section is not a claim about
        # the client's application at all — it is the one thing in the document
        # the operator has to act on because we ran the test, and a reader who
        # skims to the severity counts and stops must not miss it.
        ReportAgent._render_residual_mutations(lines, report)

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
            ReportAgent._render_component_inventory(lines, report)
            ReportAgent._render_version_match_disposition(lines, report)
            ReportAgent._render_plan_coverage(lines, report)
            ReportAgent._render_crawl_coverage(lines, report)
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
        ReportAgent._render_component_inventory(lines, report)
        ReportAgent._render_version_match_disposition(lines, report)
        ReportAgent._render_plan_coverage(lines, report)
        ReportAgent._render_crawl_coverage(lines, report)
        ReportAgent._render_research_grounding(lines, report)
        ReportAgent._render_llm_spend(lines, report)
        return "\n".join(lines)

    @staticmethod
    def _render_residual_mutations(lines: list[str], report: PentestReport) -> None:
        """What testing left on the target that the target cannot remove.

        Rendered only when there is something to report. A section that says
        "nothing was left behind" on every clean run is a section an operator
        learns to skip, which is exactly the state we need them NOT to be in on
        the run where it is populated — the same reasoning that keeps the
        component ledger from firing a permanent benign alarm.

        Every other honest-limits section in this document is about what we
        could not prove. This one is about what we DID, and its remediation is
        an instruction to the operator rather than a recommendation about their
        code.
        """
        if not report.residual_mutations:
            return
        lines.extend(
            [
                "## Changes this test left on your systems",
                "",
                "Testing this application required writing to it in a way the application "
                "itself cannot undo. These changes are still in place. They are listed "
                "here whether or not the test that caused them proved a vulnerability, "
                "because the action they require of you is the same either way.",
                "",
            ]
        )
        for mutation in report.residual_mutations:
            lines.extend(
                [
                    f"### `{mutation.key}` on {mutation.endpoint}",
                    "",
                    f"- **What happened:** {mutation.mechanism}",
                    "- **Still present:** "
                    + (
                        "yes — witnessed on a later request"
                        if mutation.witnessed
                        else "not confirmed"
                    ),
                    f"- **What you need to do:** {mutation.remediation}",
                    "",
                ]
            )
        lines.extend(["---", ""])

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
    def _parse_components(raw: object) -> list[DetectedComponent]:
        """The recon inventory, from the dict form the orchestrator hands over.

        A malformed row is dropped rather than fatal — this is the report agent,
        and a bad component row must never be the reason a client gets no
        document. Every surviving row keeps the provenance its producer
        declared; nothing here infers one, because inferring a provenance from a
        ``source`` string is the consumer-guesses-the-producer pattern this
        field exists to end.
        """
        components: list[DetectedComponent] = []
        for entry in raw or []:
            if isinstance(entry, DetectedComponent):
                components.append(entry)
            elif isinstance(entry, dict):
                try:
                    components.append(DetectedComponent.model_validate(entry))
                except Exception:  # noqa: BLE001 - a malformed row is dropped, never fatal
                    continue
        return components

    @staticmethod
    def _render_component_inventory(lines: list[str], report: PentestReport) -> None:
        """Render what was observed, ordered by how strongly it was observed.

        This is the input side of the known-CVE path, and it is rendered for the
        same reason ``plan_coverage`` and ``crawl_coverage`` are: **provenance
        decides coverage**. ``match_components`` orders confirmable-first, then
        by version provenance, then by published severity — ahead of severity
        deliberately — and the survivors claim the reserved plan slots. So the
        order of this table is the order the scarce slots were spent in, and a
        reader who wants to know why a CRITICAL was not tested can see that it
        rested on a banner while a MEDIUM rested on a lockfile.

        ``versioned`` is stated apart from the total because an unversioned
        component matches nothing version-bounded: a long inventory with few
        versions is a small CVE surface, and the total alone hides that.

        Rendered only when something was observed. An empty table would say
        nothing a black-box run against an unfingerprintable target has not
        already said in *What was NOT tested*.
        """
        inventory = report.component_inventory
        if not inventory:
            return
        rows = inventory.get("components") or []
        if not isinstance(rows, list) or not rows:
            return
        total = inventory.get("total", len(rows))
        versioned = inventory.get("versioned", 0)
        by_provenance = inventory.get("by_provenance") or {}

        lines.extend(["## Component inventory", ""])
        lines.append(
            f"{total} component(s) observed, {versioned} carrying a version. Only a "
            "versioned component can match a version-bounded CVE, so the second number "
            "is the size of the dependency surface this run could test against."
        )
        lines.append("")
        if isinstance(by_provenance, dict) and by_provenance:
            lines.append(
                "By how the version was observed: "
                + ", ".join(f"{name} {count}" for name, count in by_provenance.items())
                + "."
            )
            lines.append("")
        lines.append(
            "Ordered strongest-provenance first, which is the order the known-CVE "
            "matcher spends its reserved plan slots in. A `banner` is a string the "
            "target chose and a back-ported fix defeats it; a `lockfile` entry names "
            "what was actually resolved."
        )
        lines.extend(
            [
                "",
                "| Component | Version | Provenance | Observed by |",
                "|---|---|---|---|",
            ]
        )
        for row in rows:
            if not isinstance(row, dict):
                continue
            port = row.get("port") or 0
            observed = str(row.get("source") or "unrecorded")
            if port:
                observed += f" (port {port})"
            lines.append(
                f"| {row.get('name', '')} | {row.get('version') or '_none observed_'} "
                f"| {row.get('provenance', 'undeclared')} | {observed} |"
            )
        lines.append("")

    @staticmethod
    def _render_version_match_disposition(lines: list[str], report: PentestReport) -> None:
        """What a version match may become here — a product property, not a gap.

        The section a competitor's report does not have, and it is the point of
        the whole dependency→CVE path: **a version match is a claim about what
        is installed, never an observation of an effect.** Every other tool in
        this space prints a wall of "potentially affected" rows built from the
        same feed, and the reason they can print more rows than this is that
        they are not required to be able to prove any of them.

        So the client is told, on every run that fingerprinted anything, what
        this catalogue is bounded BY. Three sentences, and they are different
        sentences on purpose:

        * **Testable** — an oracle in this engine witnesses that CVE's defining
          effect and the input can be delivered to it. A match here becomes a
          real probe with its own control arm, and if the oracle sees nothing
          the match stays a lead. It never becomes a finding on the strength of
          a version number.
        * **No oracle, or one we cannot reach** — a real coverage boundary with
          a named fix. Stated, because "we did not test this" and "we tested
          this and it was clean" are opposite sentences and only one of them is
          true here.
        * **Band C — permanently lead-only.** Denial of service, an information
          leak observable only at a third party, a defect conditional on a
          configuration we cannot see. No future confirmation primitive moves
          these: proving a resource-exhaustion claim means degrading the
          client's own service, which the safety rails refuse on every target,
          and proving a third-party leak means standing where we are not. This
          is not a backlog item and it is not an apology.

        Computed from :data:`KNOWN_COMPONENT_CVES` rather than written down, so
        it cannot drift from the catalogue it describes — the same rule as every
        other guard here: the domain is computed, only the classification is
        declared. Rendered beside the inventory because the inventory is what
        the matcher reads; with nothing fingerprinted there is nothing to say.
        """
        inventory = report.component_inventory
        if not inventory or not (inventory.get("components") or []):
            return

        testable = [
            e
            for e in KNOWN_COMPONENT_CVES
            if e.confirming_test_method and e.vector in CARRIABLE_VECTORS
        ]
        band_c = [e for e in KNOWN_COMPONENT_CVES if e.vector in BAND_C_VECTORS]
        no_oracle = [
            e
            for e in KNOWN_COMPONENT_CVES
            if not e.confirming_test_method and e.vector not in BAND_C_VECTORS
        ]
        unreachable = [
            e
            for e in KNOWN_COMPONENT_CVES
            if e.confirming_test_method and e.vector not in CARRIABLE_VECTORS
        ]

        lines.extend(["## What a version match can become", ""])
        lines.append(
            "A component's version is a claim about what is installed. It is not an "
            "observation that anything is exploitable: a banner can be wrong, a "
            "distribution can back-port a fix without moving the number, and the "
            "vulnerable code path may be unreachable from any request. So a match in "
            "this engine becomes one of exactly two things — a test run by one of our "
            "own oracles, or a lead that states what would have proven it. It never "
            "becomes a finding on the strength of a version number alone."
        )
        lines.append("")
        lines.append(
            f"Of the {len(KNOWN_COMPONENT_CVES)} published vulnerabilities this engine "
            f"carries, **{len(testable)} are testable**: one of our oracles witnesses "
            "that CVE's defining effect, dispatches its own control arm, and decides. "
            "The catalogue is deliberately bounded by that — an entry with no oracle "
            "behind it is written down as lead-only before it is ever run, rather than "
            "discovered to be lead-only afterwards."
        )
        lines.append("")
        lines.extend(
            [
                "| Disposition | Entries | What it means for this report |",
                "|---|---|---|",
                f"| Testable | {len(testable)} | A match is probed by our own oracle. "
                "Confirmed only if that oracle witnesses the effect. |",
                f"| No oracle for the effect | {len(no_oracle)} | Reported as a lead "
                "naming the observation that would prove it. Not tested. |",
                f"| Oracle exists, input not deliverable | {len(unreachable)} | A real "
                "coverage boundary with a named fix. Not tested. |",
                f"| Band C — permanently lead-only | {len(band_c)} | No remote oracle "
                "can prove these, now or later. Always a lead. |",
            ]
        )
        lines.append("")
        if band_c:
            lines.append(
                "**On Band C.** Denial of service, memory safety, local privilege "
                "escalation, a defect conditional on a configuration we cannot observe, "
                "and an information leak whose effect is visible only at a third party "
                "are permanently lead-only here. Proving a resource-exhaustion claim "
                "means degrading your service, which this engine refuses on every "
                "target under any authorization; proving a third-party leak means "
                "observing the third party. These are reported as leads with the "
                "reason stated, never as findings and never as a coverage gap we "
                "intend to close."
            )
            lines.append("")

    @staticmethod
    def _render_crawl_coverage(lines: list[str], report: PentestReport) -> None:
        """Render what the crawl's enrichment budget never opened.

        The same rule as the plan cap above, one layer earlier: **a bound that
        decides coverage is reported in the DELIVERABLE, not just the log.** The
        plan cap decides which discovered endpoints get tested; this budget
        decides which discovered URLs ever BECOME endpoints, so everything the
        plan cap can see has already passed through it.

        On the first non-benchmark engagement 3,070 crawled URLs reduced to 212
        candidates and the budget opened 80 — 132 of them, 62% of the discovered
        surface, were never enqueued. That number existed only at INFO in the run
        log, so a reader of `report.json` had no way to know it.

        Two things are stated apart because they have different fixes. Raising
        the budget covers a truncated tail. **Hosts never opened at all** is a
        different claim: a total says how much was missed, and only the per-host
        split says whether an entire host went unlooked-at — the same reason
        every other total in this report is broken into its parts.

        And the refusal log is qualified here rather than left to imply more than
        it knows: it counts requests that were REFUSED, and this budget decides
        which candidates ever become requests, so a refusal tally describes the
        opened slice of the out-of-scope surface rather than the surface.
        """
        stamp = report.crawl_coverage
        if not stamp or not stamp.get("passes_recorded"):
            return
        lines.extend(["## Crawl coverage", ""])

        candidates = int(stamp.get("candidates") or 0)
        opened = int(stamp.get("opened") or 0)
        dropped = int(stamp.get("dropped_total") or 0)
        collapsed = int(stamp.get("duplicates_collapsed") or 0)

        if not stamp.get("crawl_truncated"):
            lines.extend(
                [
                    f"Every discovered URL worth opening was opened — {opened} of "
                    f"{candidates} candidate(s), inside the enrichment budget. No part "
                    "of the discovered surface was left unexamined by this bound.",
                    "",
                ]
            )
            return

        pct = round(100 * dropped / candidates) if candidates else 0
        lines.extend(
            [
                f"The enrichment budget opened **{opened} of {candidates} candidate "
                f"URL(s)**; **{dropped} ({pct}%) were never opened**. Those URLs were "
                "discovered and not examined, so no endpoint, parameter or form on them "
                "reached the exploit plan — nothing in this report reflects on them "
                "either way.",
                "",
                "| Host | Opened | Not opened |",
                "| --- | ---: | ---: |",
            ]
        )
        opened_by_host = stamp.get("opened_by_host") or {}
        dropped_by_host = stamp.get("dropped_by_host") or {}
        for host in sorted(set(opened_by_host) | set(dropped_by_host)):
            lines.append(
                f"| `{host}` | {int(opened_by_host.get(host) or 0)} "
                f"| {int(dropped_by_host.get(host) or 0)} |"
            )
        lines.append("")

        never = list(stamp.get("hosts_never_opened") or [])
        if never:
            lines.extend(
                [
                    f"**{len(never)} host(s) were discovered and never opened at all:** "
                    + ", ".join(f"`{h}`" for h in never)
                    + ". This is not a thin sample of them — it is none of them.",
                    "",
                ]
            )

        first_omitted = str(stamp.get("first_omitted") or "")
        if first_omitted:
            lines.extend(
                [
                    "Candidates are opened in priority order — parameterised routes and "
                    "API paths first, static assets and doubled-path artifacts last — so "
                    "what was dropped is the tail. The highest-priority URL the budget "
                    f"did not reach was `{first_omitted}`; raising the budget is what "
                    "covers it.",
                    "",
                ]
            )

        if collapsed:
            lines.extend(
                [
                    f"{collapsed} duplicate spelling(s) of already-discovered URLs were "
                    "collapsed before the budget applied, rather than each consuming a "
                    "visit.",
                    "",
                ]
            )

        lines.extend(
            [
                "This bound also qualifies the scope-refusal tally elsewhere in this "
                "report: refusals count requests that were REFUSED, and a candidate the "
                "budget never opened never became a request. The refusal counts describe "
                "the opened slice of the out-of-scope surface, not the whole of it.",
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
        # A count of 0 and no count at all are different facts: the first says
        # the phase ran and produced no technique, the second says the phase
        # never reported. ``grounding`` carries a partial signal for the second
        # (``undeclared``); the count carries none, so it does not invent one.
        raw_entries = stamp.get("runbook_entries")
        entries = (
            f"the {int(raw_entries)} runbook entr(ies)"
            if raw_entries is not None
            else "the runbook entries, whose count this run did not record,"
        )
        raw_providers = stamp.get("providers")
        providers = (
            (", ".join(str(p) for p in raw_providers) or "none")
            if raw_providers is not None
            else "not recorded"
        )
        if stamp.get("research_reported") is False:
            lines.extend(
                [
                    "**The research phase produced no record for this run** — it did not "
                    "run, errored, or was skipped. That is not the same as a research "
                    "phase that ran and found nothing, and nothing below should be read "
                    "as a measurement of what research covered.",
                    "",
                ]
            )
        if stamp.get("is_grounded"):
            lines.extend(
                [
                    f"The research behind this report was **grounded in live web search** "
                    f"(served by: {providers}). {entries[0].upper()}{entries[1:]} reflect "
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
                f"What this means for {entries} and any CVE named "
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
            lines.append(f"- Cost: {spend_cost_line(stamp)}")
        else:
            lines.append(f"- Cost: {spend_cost_line(stamp)}")
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
        # Reconciled again at RENDER time, and not only at build time. A stored
        # bundle written before the reconciliation existed still carries the
        # register's half of the disagreement, and re-rendering it must not
        # reproduce the claim its own model stamp contradicts. The rule lives in
        # one function; this is its second call site, not a second copy.
        stamp = reconcile_with_model_stamp(stamp, list(report.model_stamp))
        lines.extend(["## Provider routing", ""])
        if not stamp.get("provider_degraded"):
            lines.extend(
                [
                    "Every LLM call was served by the provider this run asked for. "
                    "No fallback activated, no provider was excluded mid-run, and no "
                    "chain was exhausted, so the run is eligible for use as a baseline.",
                    "",
                ]
            )
            return

        events = [e for e in (stamp.get("events") or []) if isinstance(e, dict)]
        absences = [a for a in (stamp.get("absences") or []) if isinstance(a, dict)]
        decision_bearing = int(stamp.get("decision_bearing_fallback_count") or 0)
        starved = list(stamp.get("exhausted_stages") or [])
        lines.extend(
            [
                f"**This run is NOT eligible as a baseline.** "
                f"{stamp.get('fallback_count', 0)} call(s) were served by a provider "
                f"other than the one asked for, and {stamp.get('absence_count', 0)} "
                f"call(s) were served by nobody at all. A number produced partly by one "
                f"model and partly by another — or produced with a reasoning step "
                f"missing — is not a measurement of the target, so nothing here should "
                f"be compared against another run's figures.",
                "",
            ]
        )
        if starved:
            lines.extend(
                [
                    f"The run's own model stamp records **no provider at all** for the "
                    f"following stage(s): {', '.join(f'`{s}`' for s in starved)}. Whatever "
                    f"those reasoning steps would have decided was decided by a default "
                    f"instead, and the phase produced its artifacts anyway.",
                    "",
                ]
            )
        if absences:
            lines.extend(
                [
                    "| Call site | Kind | Provider | Why | Decision-bearing |",
                    "| --- | --- | --- | --- | --- |",
                ]
            )
            for absence in absences:
                lines.append(
                    f"| {absence.get('call_site', '')} | {absence.get('kind', '')} | "
                    f"{absence.get('provider', '') or '(whole chain)'} | "
                    f"{absence.get('reason', '') or '-'} | "
                    f"{'yes' if absence.get('decision_bearing') else 'no'} |"
                )
            lines.append("")
        if not events:
            return
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
        ledger = reconcile_reachability_claims(
            report.component_ledger,
            run_completed=(
                report.executive_summary.run_completed if report.executive_summary else True
            ),
            incomplete_reason=(
                report.executive_summary.incomplete_reason if report.executive_summary else ""
            ),
        )
        if not ledger:
            return
        alarms = ledger.get("alarms") or []
        summary = ledger.get("summary") or {}
        correctly_empty = [c for c in (ledger.get("correctly_empty") or []) if isinstance(c, dict)]
        unreachable = [c for c in (ledger.get("unreachable") or []) if isinstance(c, dict)]
        undetermined = [
            c for c in (ledger.get("reachability_undetermined") or []) if isinstance(c, dict)
        ]
        lines.extend(["## Component contribution", ""])
        if not alarms:
            # "or were not reachable on this target" is a claim, so it is only
            # made when the run actually made that observation. A component
            # whose reachability was never determined is neither reachable nor
            # unreachable, and the all-clear must not absorb it.
            reach_clause = (
                ", or were not reachable on this target"
                if unreachable
                else ", or had their reachability left undetermined"
                if undetermined
                else ""
            )
            lines.extend(
                [
                    f"All {summary.get('components_tracked', 0)} tracked component(s) "
                    f"contributed at least one item, found nothing correctly{reach_clause}. "
                    "No fallback covered for a component that produced nothing.",
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

        if unreachable:
            # Named as a COUNT here and enumerated in report.json. Every
            # dispatchable class, route discoverer and chained tool is declared
            # on every run, so listing each one this target had no use for would
            # add dozens of lines saying nothing happened — and a section a
            # reader learns to skip is where the one line that matters hides.
            # The alarm table above is where a component that WAS reachable and
            # did not run appears.
            kinds: dict[str, int] = {}
            for rec in unreachable:
                kind = str(rec.get("kind") or "component")
                kinds[kind] = kinds.get(kind, 0) + 1
            breakdown = ", ".join(f"{count} {kind}" for kind, count in sorted(kinds.items()))
            lines.extend(
                [
                    "### Built, but not reachable on this target",
                    "",
                    f"{len(unreachable)} component(s) this engine has were never invoked "
                    f"because the engagement did not meet the condition for reaching them "
                    f"({breakdown}) — a vulnerability class whose surface this target does "
                    "not expose, a discoverer with no input of its kind, a tool whose "
                    "capability no phase asked for. Each is listed with the condition it "
                    "failed in `report.json` under `component_ledger.unreachable`. A "
                    "component that WAS reachable and still did not run is a defect and "
                    "appears in the table above, not here.",
                    "",
                ]
            )

        if undetermined:
            # The state that used to be rendered as the one above. A predicate
            # reads a phase's output, and a phase that delivered nothing made no
            # observation about this target — so the honest line names the
            # producer that was silent and stops. No per-component sentence: the
            # only sentences available are the predicate's, and those are exactly
            # the target claims this section exists to withhold.
            reasons = sorted({str(rec.get("reason") or "").strip() for rec in undetermined} - {""})
            lines.extend(
                [
                    "### Reachability not determined",
                    "",
                    f"For {len(undetermined)} component(s) this engine has, whether the "
                    "engagement could reach them was NOT determined. This is not a "
                    "statement that the target lacks their surface — it is the absence of "
                    "one. Each is named in `report.json` under "
                    "`component_ledger.reachability_undetermined` with the producer that "
                    "was silent.",
                    "",
                ]
            )
            lines.extend(f"- {reason}" for reason in reasons)
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
                f"- **Testing performed:** {testing_window(report).describe()}",
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
                verdict = authentication_state(report)
                lines.extend(
                    [
                        f"- **Mechanism:** {auth.get('mechanism', 'unknown')}",
                        f"- **Authenticated state:** {verdict.headline}",
                    ]
                )
                for line in verdict.contradictions:
                    lines.append(f"  - {line}")

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
                "for manual review. *Examined in a real browser* is not one of "
                "them: there the oracle ran and witnessed nothing, which is an "
                "answer rather than a gap.",
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
            NotTestedCategory.CLIENT_ORACLE_FOUND_NOTHING: (
                "Examined in a real browser — no execution witnessed"
            ),
            NotTestedCategory.NOT_IMPLEMENTED: "Not confirmable — no methodology",
            NotTestedCategory.DESTRUCTIVE_REFUSED: ("Refused by the production safety rails"),
            NotTestedCategory.ENGAGEMENT_HALTED: "Cut short when the engagement halted",
            NotTestedCategory.UNAUTHENTICATED: "Limited by the sessions available",
            NotTestedCategory.CLASS_ABSTAINS: (
                "Reported as a lead, not a finding — the class abstains"
            ),
        }
        rendered: set[str] = set()
        for category, heading in headings.items():
            group = [item for item in report.not_tested if item.category == category]
            if not group:
                continue
            rendered.add(str(category))
            lines.extend([f"### {heading}", ""])
            for item in group:
                lines.append(f"- **{item.item}** — {ReportAgent._not_tested_reason(report, item)}")
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
    def _not_tested_reason(report: PentestReport, item: NotTestedItem) -> str:
        """The reason to render, reconciled against the run's own output.

        The same function the PDF reads, for the same reason: a STORED bundle
        carries the sentence its original run wrote, and a header block that says
        the record and the run disagree does not un-write "Anything behind
        authentication was not examined" three sections later.
        """
        if item.category is not NotTestedCategory.UNAUTHENTICATED:
            return item.reason
        return reconciled_not_tested_reason(item.reason, authentication_state(report))

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
