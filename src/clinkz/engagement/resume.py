"""``clinkz scan --resume`` — rebuild the deliverable of an engagement that stopped.

**What this resumes is the report, not the testing, and the distinction is the
whole design.** Findings are persisted the moment they are proven (through
``_persist_finding``), and so are research- and exploit-leads, the endpoint map
and the target inventory. Phase RESULTS are not: the recon and scan models are
handed agent-to-agent in memory and never written to a table. So an engagement
killed at 80% has its proven findings on disk and its coverage state nowhere,
and the honest thing an operator can get back is the deliverable for what was
already proven.

That is worth having — a run whose report phase crashed, or one halted by the
kill switch mid-write, otherwise leaves confirmed findings sitting in SQLite
with nothing to hand anybody. It is not "carry on testing from here", and a
resumed report says so in its own *What was NOT tested* section rather than
leaving the reader to infer completeness from a document that looks finished.

Nothing here sends a request. The engagement gate is not re-opened because no
packet is emitted: re-deriving an authorization refusal over a read of local
SQLite would refuse the one operation that cannot reach the target.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from clinkz.models.scope import EngagementScope
from clinkz.state import StateStore

logger = logging.getLogger(__name__)


class ResumeError(Exception):
    """The engagement named by ``--resume`` cannot be rebuilt."""


async def regenerate_report(
    engagement_id: str,
    *,
    db_path: Path | str,
) -> dict[str, Any]:
    """Rebuild ``report_<id>.json`` / ``.md`` from an engagement's persisted state.

    Args:
        engagement_id: The engagement to rebuild. Must exist in the state store.
        db_path: The SQLite state store holding it.

    Returns:
        The report agent's result dict (``json_path``, ``markdown_path``,
        ``status``, and the report itself), plus ``engagement_id``,
        ``engagement_name`` and the original ``original_status``.

    Raises:
        ResumeError: No engagement with that id exists in this state store.
    """
    # Imported here rather than at module scope: ReportAgent pulls in the agent
    # stack, and this module is imported by the CLI at option-parse time.
    from clinkz.agents.report import ReportAgent

    async with StateStore(db_path) as state:
        record = await state.get_engagement(engagement_id)
        if record is None:
            raise ResumeError(
                f"No engagement {engagement_id!r} in {db_path}. "
                "Pass the UUID printed at the start of the run (also the directory "
                "name under the outputs root), and point --db at the same state "
                "store the run used."
            )

        scope = _rebuild_scope(record)
        authorization = scope.authorization

        findings = await state.get_findings(engagement_id, validated_only=False)
        leads = await state.get_research_leads(engagement_id)
        logger.info(
            "Resuming engagement %s (%s, status=%s): %d persisted finding(s), %d lead(s)",
            engagement_id,
            record.get("name", ""),
            record.get("status", ""),
            len(findings),
            len(leads),
        )

        agent = ReportAgent(
            llm=None,  # type: ignore[arg-type] — the report agent makes zero LLM calls
            tools=[],
            scope=scope,
            state=state,
            engagement_id=engagement_id,
        )
        result = await agent.run(
            {
                "engagement_id": engagement_id,
                "engagement_name": record.get("name") or "Penetration Test",
                "authorization": authorization.model_dump(mode="json") if authorization else None,
                "scope_in": [f"{t.value} ({t.type.value})" for t in scope.targets],
                "scope_out": [
                    f"{e.value} ({e.type.value})" + (f" — {e.notes}" if e.notes else "")
                    for e in scope.excluded
                ],
                "rules_of_engagement": list(scope.rules_of_engagement),
                "engagement_window": scope.window.model_dump(mode="json") if scope.window else None,
                # Deliberately not the original run's governor stats: those live
                # in memory and are gone. Reporting a blank safety summary is
                # accurate; reconstructing plausible numbers would not be.
                "safety": {},
                "authentication": {},
                # The line that keeps the deliverable honest about its own origin.
                "resumed_from": engagement_id,
            }
        )

    result["engagement_id"] = engagement_id
    result["engagement_name"] = record.get("name") or ""
    result["original_status"] = record.get("status") or ""
    result["findings_persisted"] = len(findings)
    result["leads_persisted"] = len(leads)
    return result


def _rebuild_scope(record: dict[str, Any]) -> EngagementScope:
    """Rebuild the engagement scope from its persisted JSON.

    A scope that no longer validates (written by an older schema, or truncated)
    degrades to a minimal one carrying the engagement name, so a rebuild still
    produces the findings rather than failing on the header. The degradation is
    logged; it is not silent.
    """
    raw = record.get("scope") or {}
    try:
        return EngagementScope.model_validate(raw)
    except ValueError as exc:
        logger.warning(
            "Persisted scope for engagement %s does not validate (%s) — rebuilding "
            "the report with a minimal scope; the header will be sparse.",
            record.get("id"),
            exc,
        )
        return EngagementScope(name=str(record.get("name") or "resumed engagement"), targets=[])


__all__ = ["ResumeError", "regenerate_report"]
