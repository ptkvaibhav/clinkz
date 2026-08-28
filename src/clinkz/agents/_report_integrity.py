"""What the report may CLAIM, reconciled against the run's own record.

Three sections of the deliverable read one field each and stated a conclusion
the rest of the document contradicted. That is a worse failure than a missing
section, because a client reads the conclusion and has no reason to check it.

* **The testing window.** ``test_start`` and ``test_end`` both defaulted to the
  report-generation clock — nobody ever passed either — so both generated PDFs
  render ``test_start == test_end``. A run of 4,597s says zero, immediately
  under the authorized window, where that line is the report's own evidence
  that testing happened inside it. The window now comes from the governor,
  which is the one component that sees every dispatched request.

* **Authentication.** ``authenticated`` is one boolean, and the negative branch
  renders the strongest sentence in the header — "Anything behind authentication
  was not examined" — above 22 findings sitting behind DVWA's login. A negative
  claim is only as good as the check that produced it, and in that run no check
  ran at all: ``assertion`` is ``null``. The three states are told apart here.

* **Cost.** ``$0.00`` with a lower-bound caveat reads as a wrong number. An
  engagement whose models carry no declared rate has no price, and "not priced"
  is what that is.

* **Reachability.** ``component_ledger.unreachable`` renders one sentence per
  component about what this target does not expose. Those sentences are worth
  what the phase that observed them is worth, and a document whose own banner
  says the run did not complete must not carry target claims derived from the
  phase that did not. They become "not determined" here.

Every function is pure and reads only what the ENGINE declared, so it holds at
both seams — the build seam, so ``report.json`` carries the reconciled claim,
and the render seam, so a stored bundle re-renders honestly. Same shape, and the
same reason, as ``reconcile_with_model_stamp``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from clinkz.models.report import PentestReport

__all__ = [
    "AuthenticationState",
    "AuthenticationVerdict",
    "assert_testing_window_renderable",
    "TestingWindow",
    "TestingWindowError",
    "authentication_state",
    "authentication_verdict",
    "document_title",
    "primary_scope_label",
    "reconcile_reachability_claims",
    "reconciled_not_tested_reason",
    "spend_cost_line",
    "testing_window",
]


# ---------------------------------------------------------------------------
# The testing window
# ---------------------------------------------------------------------------


class TestingWindowError(RuntimeError):
    """A render that would state a testing window the run's own record refutes.

    Raised rather than absorbed. A document whose "testing performed" line is
    the report-generation clock is making a claim about when the engagement
    touched the client's estate, and it renders directly beneath the authorized
    window — so a wrong value there is not a cosmetic defect, it is the report
    failing to evidence the one thing the window section exists to evidence.
    """


@dataclass(frozen=True)
class TestingWindow:
    """When the engagement's requests actually started and stopped.

    Attributes:
        start: First dispatched request, or the report's own ``test_start`` when
            no window was recorded.
        end: Last dispatched request, likewise.
        recorded: Whether a real window was stamped by the governor. ``False``
            means the run sent requests through no governor, or the bundle
            predates the stamp.
        requests_sent: Whether the run's own safety summary says any request was
            authorized. This is what makes a degenerate window a defect rather
            than the truthful answer for a ``--dry-run``.
        duration_seconds: ``end - start`` in seconds, ``0.0`` when unrecorded.
        source: Where the window came from, when it did not come from the
            governor's own live stamp. A window RECOVERED from a stored bundle's
            action log is narrower than the governor's — the log records
            state-changing requests and browser navigations, not every GET — so
            the provenance renders beside it rather than being folded away.
    """

    start: datetime
    end: datetime
    recorded: bool
    requests_sent: bool
    duration_seconds: float
    source: str = ""

    @property
    def is_degenerate(self) -> bool:
        """Whether the window claims zero elapsed time."""
        return self.end <= self.start

    def describe(self) -> str:
        """One line for the header block, in every document.

        Never renders a zero-length window as though it were measured: the two
        cases it cannot distinguish — "nothing was sent" and "nobody recorded
        it" — are stated as themselves.
        """
        if self.recorded:
            provenance = f", {self.source}" if self.source else ""
            return (
                f"{self.start.isoformat()} → {self.end.isoformat()} "
                f"({self.duration_seconds:,.0f}s{provenance})"
            )
        if self.requests_sent:
            return (
                "not recorded — this engagement's requests were not stamped with a "
                "window, so the times below are the report-generation clock and are NOT "
                "evidence of when testing ran"
            )
        return "no request was dispatched"


def _summary_int(summary: dict[str, Any], key: str) -> int:
    value = summary.get(key)
    return int(value) if isinstance(value, int | float) else 0


def _parse_stamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


def testing_window(report: PentestReport) -> TestingWindow:
    """The engagement's request window, read from the governor's own stamp.

    The stamp lives in ``safety_summary`` because the governor produces it, and
    the governor is the only component every dispatched request passes through.
    Its ABSENCE is load-bearing: a bundle written before the stamp existed has
    no key at all, which is how :func:`assert_testing_window_renderable` tells a
    missing record apart from a new bundle that is lying.

    Args:
        report: The already-redacted report.

    Returns:
        A :class:`TestingWindow`. Falls back to the report's own ``test_start`` /
        ``test_end`` when no stamp is present, with ``recorded=False``.
    """
    summary = report.safety_summary or {}
    requests_sent = bool(
        _summary_int(summary, "requests_authorized")
        or _summary_int(summary, "state_changing_sent")
        or _summary_int(summary, "browser_navigations")
    )
    first = _parse_stamp(summary.get("first_request_at"))
    last = _parse_stamp(summary.get("last_request_at"))
    if first is not None and last is not None and last > first:
        return TestingWindow(
            start=first,
            end=last,
            recorded=True,
            requests_sent=requests_sent,
            duration_seconds=(last - first).total_seconds(),
            source=str(summary.get("request_window_source") or ""),
        )
    # No stamp, or a stamp that spans one instant. Both fall back to whatever
    # the report carries, flagged as unrecorded so no renderer prints it as a
    # measurement.
    return TestingWindow(
        start=report.test_start,
        end=report.test_end,
        recorded=report.test_end > report.test_start,
        requests_sent=requests_sent,
        duration_seconds=max(0.0, (report.test_end - report.test_start).total_seconds()),
    )


def assert_testing_window_renderable(report: PentestReport) -> TestingWindow:
    """Refuse to render a document whose testing window contradicts its own run.

    The rule is: *whenever any request was sent, ``test_end`` must be greater
    than ``test_start``*. The one exception is a bundle that carries no window
    stamp at all — those predate the stamp, and there is no honest value to
    substitute, so they render :meth:`TestingWindow.describe`'s explicit "not
    recorded" instead. A bundle written by this version always carries the key,
    so a new bundle with a degenerate window is a defect and fails loudly.

    Args:
        report: The already-redacted report.

    Returns:
        The reconciled :class:`TestingWindow`.

    Raises:
        TestingWindowError: A stamped window is degenerate while requests were
            sent.
    """
    window = testing_window(report)
    summary = report.safety_summary or {}
    stamped = "first_request_at" in summary
    if stamped and window.requests_sent and not window.recorded:
        raise TestingWindowError(
            "the run authorized requests but its testing window spans no time "
            f"({window.start.isoformat()} → {window.end.isoformat()}) — a "
            "'testing performed' line taken from the report-generation clock is the "
            "report's own evidence that testing happened inside the authorized window, "
            "and it would be evidence of the wrong thing"
        )
    return window


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


class AuthenticationState(StrEnum):
    """How much the run actually knows about its own authenticated state."""

    #: An assertion ran and a boundary discriminator established the session.
    PROVEN = "proven"
    #: An assertion ran and did NOT establish one. A real negative, with evidence.
    DISPROVEN = "disproven"
    #: The record says no session, and the run's own output says otherwise —
    #: session material was held, or findings were produced while the question
    #: was never asked. The report may not assert the negative here.
    INCONSISTENT = "inconsistent"
    #: No session, nothing contradicting that, nothing to reconcile.
    NOT_ATTEMPTED = "not_attempted"


@dataclass(frozen=True)
class AuthenticationVerdict:
    """The reconciled authentication claim, and what backs it.

    Attributes:
        state: Which of the four situations this run is in.
        headline: The sentence the header block renders.
        contradictions: Engine-authored facts that refuted the record, empty
            unless ``state`` is :attr:`AuthenticationState.INCONSISTENT`.
    """

    state: AuthenticationState
    headline: str
    contradictions: tuple[str, ...] = ()

    @property
    def may_assert_no_session(self) -> bool:
        """Whether the document may say the authenticated surface went untested.

        False for :attr:`AuthenticationState.INCONSISTENT`, which is the whole
        point: 3c47a0de rendered "Anything behind authentication was not
        examined" above 22 findings at ``/vulnerabilities/sqli/``, ``/exec/``,
        ``/fi/`` and ``/upload/``, every one of them behind DVWA's login.
        """
        return self.state in (AuthenticationState.DISPROVEN, AuthenticationState.NOT_ATTEMPTED)


def authentication_state(report: PentestReport) -> AuthenticationVerdict:
    """Reconcile a finished report's authentication record. See :func:`authentication_verdict`."""
    return authentication_verdict(dict(report.authentication or {}), len(report.findings))


def authentication_verdict(auth: dict[str, Any], finding_count: int) -> AuthenticationVerdict:
    """Reconcile the authentication record against the rest of the document.

    Reads only engine-authored fields — the assertion the orchestrator ran, the
    session material it held, and the findings it emitted. A response body has no
    route into any of them, which is the same rule ``_evidence_strength`` and the
    control-arm reader follow.

    Two facts can refute a ``authenticated=false`` record:

    1. **Session material held.** The engagement proved a credential valid and
       kept its session. That is the default-credential sweep's case: it logged
       in on all four DVWA ladder levels and wrote the session to the credential
       store, which every later phase reads, while ``_role_sessions`` and
       ``_auth_assertion`` — the only two fields the report renders — stayed
       empty.
    2. **Findings with no assertion.** The record claims no session AND no
       assertion was ever run, yet the run produced confirmed findings. A
       negative claim resting on a check that never executed is the same defect
       as "0 findings identified. Risk rating: Informational."

    Args:
        auth: The authentication summary the orchestrator produced.
        finding_count: How many confirmed findings the run emitted. Taken as a
            number rather than read off the report, so the same reconciliation
            runs at the BUILD seam — where ``not_tested`` is assembled and no
            report object exists yet — and at the render seam.

    Returns:
        An :class:`AuthenticationVerdict`.
    """
    if not auth:
        return AuthenticationVerdict(
            state=AuthenticationState.NOT_ATTEMPTED,
            headline="no authentication was attempted for this engagement",
        )

    assertion = auth.get("assertion")
    assertion_ran = isinstance(assertion, dict) and bool(assertion)
    if auth.get("authenticated"):
        return AuthenticationVerdict(
            state=AuthenticationState.PROVEN,
            headline="PROVEN",
        )

    contradictions: list[str] = []
    if auth.get("session_material_held"):
        source = str(auth.get("session_source") or "an unnamed source")
        contradictions.append(
            f"the engagement held session material obtained by {source}, and carried it on "
            "subsequent requests"
        )
    if finding_count and not assertion_ran:
        contradictions.append(
            f"{finding_count} confirmed finding(s) were produced while no "
            "authenticated-state assertion was ever run, so the record is an absence of "
            "evidence rather than evidence of absence"
        )

    if contradictions:
        return AuthenticationVerdict(
            state=AuthenticationState.INCONSISTENT,
            headline=(
                "INCONSISTENT — session evidence present, record absent. This "
                "engagement's authentication record says no session was established, and "
                "the run's own output contradicts it. Treat the coverage below as "
                "authenticated-or-not unknown rather than as unauthenticated-only"
            ),
            contradictions=tuple(contradictions),
        )
    if assertion_ran:
        why = str(assertion.get("why_unproven") or "").strip()  # type: ignore[union-attr]
        return AuthenticationVerdict(
            state=AuthenticationState.DISPROVEN,
            headline=(
                "NOT established — the authenticated-state assertion ran and no "
                "authorization boundary discriminator was found" + (f": {why}" if why else "")
            ),
        )
    return AuthenticationVerdict(
        state=AuthenticationState.NOT_ATTEMPTED,
        headline=(
            "NOT established — this engagement examined only the surface reachable without a login"
        ),
    )


def reconciled_not_tested_reason(item_reason: str, verdict: AuthenticationVerdict) -> str:
    """Rewrite a stored *unauthenticated* limitation the run's own output refutes.

    The reconciliation has to run at BOTH seams for the same reason
    ``reconcile_with_model_stamp`` does. At the build seam this reason is written
    correctly in the first place; at the render seam a STORED bundle carries the
    sentence its original run wrote, and re-rendering it verbatim would put
    "Anything behind authentication was not examined" three pages after a header
    block that says the record and the run disagree. A document that contradicts
    itself across two sections is the defect, whichever section is right.

    Only ever tightens: a reason the verdict supports is returned unchanged. That
    also keeps the OTHER ``UNAUTHENTICATED`` item — "only one authenticated role
    was available" — out of its way: that one is written on the ``authenticated``
    branch, so its verdict is ``PROVEN`` and this returns it untouched.

    Args:
        item_reason: The stored ``NotTestedItem.reason``.
        verdict: The reconciled authentication verdict.

    Returns:
        The reason to render.
    """
    if verdict.may_assert_no_session or verdict.state is AuthenticationState.PROVEN:
        return item_reason
    return (
        "This engagement's authentication record says no session was established and the "
        "run's own output contradicts it, so the authenticated surface can be reported "
        "neither as tested nor as untested. " + " ".join(verdict.contradictions)
    )


# ---------------------------------------------------------------------------
# Cost, and the document's own name
# ---------------------------------------------------------------------------


def spend_cost_line(spend: dict[str, Any] | None) -> str:
    """The cost line, or an honest statement that there is no price.

    ``$0.00`` beside "a LOWER BOUND" reads as a wrong number rather than an
    honest one: the engagement did not cost nothing, it consumed 92,225 tokens
    of a model with no declared rate. When nothing was priced there is no dollar
    figure to render and the document says so.

    Args:
        spend: The report's ``llm_spend`` block.

    Returns:
        A ready-to-render string.
    """
    spend = spend or {}
    usd = spend.get("usd_spent")
    complete = bool(spend.get("usd_is_complete"))
    unpriced = [str(m) for m in (spend.get("unpriced_models") or [])]
    priced = isinstance(usd, int | float) and usd > 0
    if complete and isinstance(usd, int | float):
        return f"${usd:.2f}"
    if not priced:
        detail = f" (no declared rate for: {', '.join(unpriced)})" if unpriced else ""
        return f"not priced{detail}"
    detail = f"; no declared rate for: {', '.join(unpriced)}" if unpriced else ""
    return f"at least ${usd:.2f} (a LOWER BOUND{detail})"


def primary_scope_label(report: PentestReport) -> str:
    """The engagement's primary target, stripped of the scope entry's annotations.

    ``target_scope`` entries are rendered for the scope section and carry their
    classification and original target — ``http://clinkz-dvwa:80 (url) —
    original_target=http://localhost:8080``. That is the right string for the
    scope list and the wrong one for a title.
    """
    for entry in report.target_scope:
        head = str(entry).split(" (")[0].split(" — ")[0].strip()
        if head:
            return head
    return "unspecified scope"


def document_title(report: PentestReport) -> str:
    """One rule for what the document is called, used by every title site.

    The two generated PDFs are titled by two different rules today, because
    ``EngagementScope.name`` is the operator's ``--scope`` label when one was
    supplied and the raw ``--target`` string when one was not. Two bundles that
    cannot be told apart by their titles cannot be filed beside each other, so
    the title always names the target and adds the operator's label only when
    that label says something the target does not.

    Args:
        report: The already-redacted report.

    Returns:
        ``"<label> - <target>"`` or ``"<target>"``.
    """
    target = primary_scope_label(report)
    label = str(report.engagement_name or "").strip()
    # A label the scope entry ALREADY carries adds nothing. The CLI names an
    # engagement after its raw ``--target`` when no scope document was supplied,
    # and docker tool-mode then rewrites that target to a container alias — so
    # the scope entry reads ``http://clinkz-dvwa:80 (url) —
    # original_target=http://localhost:8080`` and the "label" is the second half
    # of it. Matched against the WHOLE entry, not the trimmed head.
    scope_text = " ".join(str(entry) for entry in report.target_scope)
    if not label or label in scope_text or target in label:
        return target
    return f"{label} — {target}"


# ---------------------------------------------------------------------------
# Reachability claims vs. the run-completion banner
# ---------------------------------------------------------------------------


#: Why a reachability verdict cannot stand over an incomplete run. One sentence,
#: written once, interpolated with what the banner already says did not finish.
_INCOMPLETE_RUN_REACHABILITY = (
    "the run did not complete, so whether this component was reachable is not determined: {reason}"
)


def reconcile_reachability_claims(
    ledger: dict[str, Any] | None,
    *,
    run_completed: bool,
    incomplete_reason: str = "",
) -> dict[str, Any]:
    """Move every reachability CLAIM out of an incomplete run's ledger.

    ``component_ledger.unreachable`` carries one sentence per component saying
    what this target does not expose — no endpoint with this class's surface, no
    HTTP surface for a discoverer to read. Those are claims about the client's
    application, and they are only worth what the phase that observed them is
    worth. A document whose own executive summary says the run did not complete
    must not carry target claims derived from the phase that did not.

    The orchestrator's source gating already covers a phase that delivered no
    result. This covers the other way in, which that cannot see: a phase that
    delivered a result whose reasoning step nothing served. ``model_stamp``
    naming an exhausted stage is exactly that — the plan is empty because the
    planner was starved, not because the target has no surface — and
    ``_run_completion`` is the one place both witnesses are already reconciled.

    Only ever TIGHTENS: a claim becomes "not determined", never the reverse, and
    a completed run is returned unchanged. Pure, and reads only engine-declared
    fields, so it holds at the build seam (``report.json`` carries the reconciled
    ledger) and at the render seam (a stored bundle re-renders honestly). Same
    shape, same reason, as ``reconcile_with_model_stamp``.

    Args:
        ledger: The ``component_ledger`` dict, or ``None``/``{}`` when no ledger
            was installed.
        run_completed: ``ExecutiveSummary.run_completed``.
        incomplete_reason: ``ExecutiveSummary.incomplete_reason``, quoted into
            the substituted sentence so the two cannot disagree.

    Returns:
        The ledger, reconciled. The input dict is never mutated.
    """
    if not isinstance(ledger, dict) or not ledger:
        return ledger if isinstance(ledger, dict) else {}
    unreachable = [c for c in (ledger.get("unreachable") or []) if isinstance(c, dict)]
    if run_completed or not unreachable:
        return ledger

    reason = _INCOMPLETE_RUN_REACHABILITY.format(
        reason=incomplete_reason.strip() or "one or more phases did not finish."
    )
    undetermined = [
        c for c in (ledger.get("reachability_undetermined") or []) if isinstance(c, dict)
    ]
    out = dict(ledger)
    out["unreachable"] = []
    out["reachability_undetermined"] = undetermined + [
        {
            "component": entry.get("component", "?"),
            "kind": entry.get("kind", "component"),
            "predicate": entry.get("predicate", ""),
            "reason": reason,
        }
        for entry in unreachable
    ]
    summary = dict(ledger.get("summary") or {})
    if summary:
        summary["unreachable_components"] = 0
        summary["reachability_undetermined_components"] = len(out["reachability_undetermined"])
        out["summary"] = summary
    return out
