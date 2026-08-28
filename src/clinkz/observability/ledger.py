"""Per-run component-contribution ledger — the gate against silent degradation.

Three separate defects shipped with the same shape, and none of them tripped a
gate:

* the LLM planner returned an empty completion and the per-class floor covered
  for it, so a plan still existed;
* an LLM call timed out and provider fallback covered for it, so an answer still
  arrived;
* 100% of ffuf's output was discarded by a duck-typed seam and the crawler
  covered for it, so endpoints still existed.

Every time, a component produced **nothing**, something else covered, findings
still appeared, and the run looked healthy. A total is not evidence about its
parts: a pipeline that reports 21 findings while a whole discovery tool
contributes zero is indistinguishable, from the outside, from one where it
contributed half of them.

The ledger measures the parts. Each component records what it was **asked** to
do (invocations), what came back (successes/failures), and — the number none of
the three defects would have survived — how many **items it actually
contributed**. At the end of the run every component that was invoked and
contributed nothing is reported loudly, in the run log and in ``report.json``.

Design constraints, each earned:

* **Absent by default.** :func:`get_active_ledger` is ``None`` unless an
  engagement installed one, and every helper here no-ops in that case. A smoke
  cell, a replay, or a directly-invoked methodology is byte-identical with the
  ledger in the tree — the same rule the safety governor follows.
* **Never raises from the data path.** An observability layer that can abort a
  scan is worse than the blindness it fixes. Every public function swallows its
  own errors.
* **"Declared but never invoked" is a different fact from "invoked and
  contributed nothing".** The first is a capability the run never reached for;
  the second is a component that ran and produced nothing. Conflating them
  produces either false alarms or the silence this module exists to end.
* **A structurally dead seam outranks a quiet one.** A consumer reading a
  producer that *cannot* answer it (the ffuf shape) is not a component having a
  slow day — it is a capability that has never worked. It gets its own alarm
  class and its own wording.
* **"Correctly found nothing" is a third fact again, and it is not an alarm.**
  A GraphQL discoverer on an application that serves no GraphQL contributes
  zero on every run, forever, and is working perfectly. Reported as a defect it
  becomes a permanent false alarm — and a permanent false alarm trains an
  operator to skim past the line where a real one will eventually appear. So a
  component may report that its *precondition was absent*, and the zero is then
  recorded as NOT APPLICABLE with the reason, held apart from the alarm list
  exactly like "declared but never invoked".

  The distinction has to be **falsifiable**, not a self-assessment: a component
  claiming "nothing to find" is making the same noise as one that is broken.
  What separates them is how far its own pipeline got. A discoverer that read
  no input of its kind, or read input containing nothing of the shape it looks
  for, found nothing correctly. One that found candidates and emitted none
  converted 100% of real input into nothing — the ffuf shape — and stays a
  SILENT alarm. The caller decides which of those happened, because only the
  caller knows the component's stages; the ledger only refuses to conflate them.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)

#: Cap on notes kept per component. A run makes thousands of calls; the ledger
#: is a summary, not a second trace.
_MAX_NOTES = 8


class ComponentKind(StrEnum):
    """What kind of thing a ledger entry describes.

    The kind decides the wording of the alarm, not its severity — a discovery
    tool contributing nothing and an LLM planner contributing nothing are the
    same defect wearing different clothes.
    """

    LLM = "llm"
    LLM_PROVIDER = "llm_provider"
    TOOL = "tool"
    PARSER_SEAM = "parser_seam"
    DISCOVERER = "discoverer"
    METHODOLOGY = "methodology"
    #: A component whose input is the engine's OWN confirmed output rather than
    #: the target — the chain planner is the first. Its silent-degradation mode is
    #: distinct and worth naming: it can be invoked on every run, succeed on every
    #: run, and compose nothing because the vocabulary it reads has a gap. That
    #: reads as "no chains existed" and is indistinguishable from a healthy run
    #: against an application with no chains, which is exactly the shape this
    #: ledger exists to make visible.
    COMPOSER = "composer"


class LedgerAlarm(StrEnum):
    """Why a component is being reported.

    Ordered most-severe first when rendered.
    """

    #: The consumer reads a producer that structurally cannot answer it. This
    #: capability has never worked and never will until the seam is fixed.
    DEAD_SEAM = "dead_seam"
    #: Invoked at least once, succeeded at least once, contributed zero items.
    SILENT = "silent"
    #: Invoked, and every invocation failed. Loud already, but recorded so the
    #: end-of-run summary is complete.
    ALL_FAILED = "all_failed"
    #: Declared, never invoked, and its reachability predicate says the run
    #: COULD have reached it. Distinct from SILENT — that component ran and
    #: produced nothing; this one never ran at all, and the engine can state the
    #: engagement condition that made it available. Held apart because the fixes
    #: differ completely: a silent component has a broken seam or an empty
    #: answer, an unreached one has a dispatcher, a gate or a plan that skipped
    #: it. Never fires when reachability was not evaluated.
    BUILT_BUT_NOT_RUN = "built_but_not_run"
    #: Something covered for this component. Not a defect on its own — a
    #: fallback that activates is doing its job — but it is the mechanism that
    #: hid all three defects, so it is never invisible again.
    FALLBACK_ACTIVATED = "fallback_activated"


@dataclass
class ComponentRecord:
    """One component's contribution over an engagement."""

    name: str
    kind: ComponentKind
    invocations: int = 0
    successes: int = 0
    failures: int = 0
    items_contributed: int = 0
    fallback_activations: int = 0
    dead_seam: bool = False
    #: Successful invocations that reported their own precondition absent —
    #: nothing of the kind this component reads was present on the target. Kept
    #: apart from ``successes`` rather than deducted from it, because the
    #: invocation really did happen and really did succeed.
    not_applicable: int = 0
    #: Why the precondition was absent, in the component's own words. One per
    #: distinct reason, bounded like ``notes``.
    not_applicable_reasons: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    #: The reachability predicate this component declared at engagement start
    #: (a ``ReachabilityKey`` value), or ``""`` for a component that registered
    #: by being invoked without ever being declared.
    declared_reachability: str = ""
    #: The predicate's verdict, or ``None`` when it was never evaluated — a
    #: direct invocation, a run that stopped before the report. ``None`` is not
    #: ``False``: an un-evaluated predicate makes no claim in either direction,
    #: and must never produce an alarm.
    reachable: bool | None = None
    #: The predicate's own sentence for why the component was unreachable.
    #: Written by the predicate, not by the component, so it cannot drift entry
    #: by entry the way a per-component reason string does. Set through
    #: :meth:`set_reachability`, never assigned directly — see that method for
    #: why the redaction has to live at the property.
    reachability_reason: str = ""
    #: Why the predicate could not be evaluated at all — the producer it reads
    #: delivered nothing this run. Non-empty means ``reachable is None`` was a
    #: DECISION rather than an absence of one, and it is what the deliverable
    #: renders in place of a reachability verdict. Set through
    #: :meth:`set_reachability_undetermined`.
    reachability_undetermined: str = ""

    def add_note(self, note: str) -> None:
        """Append a bounded, deduplicated, REDACTED note.

        Redacted at ingestion rather than at each writer, because the notes go
        two ways and only one of them is protected. ``report.json`` is written
        through ``redact_structure``; :meth:`ContributionLedger.log_summary`
        writes the same notes straight to the run log, which is not.

        A note is not always a string this module authored. ``_run_sqlmap``
        records ``str(exc)[:120]`` from a failed tool invocation, and a tool's
        own error text can carry the argv that produced it — a ``--cookie``
        bearing the engagement's live session. LESSONS #47 is exactly this
        shape: a login curl's argv went verbatim into ``trace.jsonl`` because
        redaction was applied at the writer someone remembered rather than at
        the property. Applying it here makes every downstream consumer safe by
        construction instead of by discipline.
        """
        if not note or len(self.notes) >= _MAX_NOTES:
            return
        try:
            from clinkz.engagement.secrets import redact

            note = redact(note)
        except Exception as exc:  # noqa: BLE001 — never raise from the data path
            logger.debug("Ledger note redaction failed: %s", exc)
            return
        if note not in self.notes:
            self.notes.append(note)

    def add_not_applicable_reason(self, reason: str) -> None:
        """Record why the precondition was absent — bounded, deduped, REDACTED.

        Redacted at the property for exactly the reason :meth:`add_note` is, and
        the reason goes to the same two places: ``report.json``, which its
        writer redacts, and :meth:`ContributionLedger.log_summary`, which writes
        to the run log and does not. Today every caller passes engine-authored
        text, so there is nothing to catch. That is the argument for applying it
        here rather than against — LESSONS #47 is a credential that reached an
        artifact because redaction was applied at the writer someone remembered
        instead of at the property. A field this one is a sibling of already
        learned that.
        """
        if not reason or len(self.not_applicable_reasons) >= _MAX_NOTES:
            return
        try:
            from clinkz.engagement.secrets import redact

            reason = redact(reason)
        except Exception as exc:  # noqa: BLE001 — never raise from the data path
            logger.debug("Ledger not-applicable reason redaction failed: %s", exc)
            return
        if reason not in self.not_applicable_reasons:
            self.not_applicable_reasons.append(reason)

    def set_reachability(self, reachable: bool, reason: str) -> None:
        """Record a predicate's verdict and its REDACTED sentence.

        Redacted here rather than at the predicate, for the third time in this
        class and for the same reason ``add_note`` and
        ``add_not_applicable_reason`` are: this string goes two ways and only one
        of them is protected. ``report.json`` is written through
        ``redact_structure``; :meth:`ContributionLedger.log_summary` writes the
        same string straight to the run log, which is not.

        Every predicate authors engine text today — component names, capability
        keys, counts — so there is nothing to catch. That is the argument for
        applying it here rather than against: LESSONS #47 is a credential that
        reached an artifact because redaction sat at the writer someone
        remembered instead of at the property, and the next predicate to be
        written will interpolate whatever engagement state it needs.

        A failed redaction drops the sentence rather than emitting it raw — the
        component is still recorded as unreachable, which is the load-bearing
        half, and an unredactable reason is exactly the one not to print.
        """
        self.reachable = reachable
        if not reachable and reason:
            try:
                from clinkz.engagement.secrets import redact

                self.reachability_reason = redact(reason)
            except Exception as exc:  # noqa: BLE001 — never raise from the data path
                logger.debug("Ledger reachability reason redaction failed: %s", exc)
                self.reachability_reason = ""
        else:
            self.reachability_reason = ""
        self.reachability_undetermined = ""

    def set_reachability_undetermined(self, reason: str) -> None:
        """Record that no predicate could be evaluated, and why.

        The producer this component's predicate reads delivered nothing, so the
        predicate's counters carry defaults rather than measurements. Evaluating
        it anyway answers ``False`` and writes the predicate's sentence — a claim
        about the target's surface — out of a phase that never ran.

        ``reachable`` deliberately stays ``None``: it is not ``False`` (which
        would file the component NOT APPLICABLE and put that sentence in the
        deliverable) and it is not ``True`` (which would alarm). The reason
        string is what separates this from the other ``None`` — a component
        nobody ever evaluated, in a replay or a direct invocation.

        Redacted at the property for the same reason :meth:`set_reachability` is,
        and a failed redaction drops the sentence while keeping the state: the
        load-bearing half is that no verdict was reached.
        """
        self.reachable = None
        self.reachability_reason = ""
        if not reason:
            self.reachability_undetermined = ""
            return
        try:
            from clinkz.engagement.secrets import redact

            self.reachability_undetermined = redact(reason)
        except Exception as exc:  # noqa: BLE001 — never raise from the data path
            logger.debug("Ledger undetermined-reachability reason redaction failed: %s", exc)
            self.reachability_undetermined = "reachability was not determined for this run"

    @property
    def correctly_empty(self) -> bool:
        """Whether every successful invocation found nothing *correctly*.

        True only when the component contributed nothing AND each success
        reported its own precondition absent. One success that examined real
        input and produced nothing anyway is enough to make this False — that
        one is the defect shape, and it must not be absorbed by the others.
        """
        return (
            self.invocations > 0
            and self.successes > 0
            and self.items_contributed == 0
            and self.not_applicable >= self.successes
        )

    @property
    def alarms(self) -> list[LedgerAlarm]:
        """Every alarm class this record currently trips.

        A component can trip more than one: a dead seam that a fallback covered
        for is both facts at once, and reporting only the first would hide the
        one the operator needs.
        """
        out: list[LedgerAlarm] = []
        if self.dead_seam:
            out.append(LedgerAlarm.DEAD_SEAM)
        if self.invocations == 0 and self.reachable is True and not self.dead_seam:
            # Built, reachable this engagement, and it did not run. ``is True``
            # rather than a truthiness test: ``None`` means the predicate was
            # never evaluated, and an un-evaluated predicate is not a claim that
            # the component was unreachable — it is no claim at all.
            out.append(LedgerAlarm.BUILT_BUT_NOT_RUN)
        if self.invocations > 0 and self.successes == 0:
            out.append(LedgerAlarm.ALL_FAILED)
        elif self.invocations > 0 and self.items_contributed == 0 and not self.correctly_empty:
            # Succeeded at least once, examined real input, produced nothing.
            # The defect shape — and NOT the "this target has no GraphQL" shape,
            # which reports its own absent precondition and is listed separately.
            out.append(LedgerAlarm.SILENT)
        if self.fallback_activations > 0:
            out.append(LedgerAlarm.FALLBACK_ACTIVATED)
        return out

    def to_dict(self) -> dict[str, Any]:
        """Render for ``report.json``."""
        return {
            "component": self.name,
            "kind": self.kind.value,
            "invocations": self.invocations,
            "successes": self.successes,
            "failures": self.failures,
            "items_contributed": self.items_contributed,
            "fallback_activations": self.fallback_activations,
            "not_applicable": self.not_applicable,
            "not_applicable_reasons": list(self.not_applicable_reasons),
            "correctly_empty": self.correctly_empty,
            "declared_reachability": self.declared_reachability,
            "reachable": self.reachable,
            "reachability_reason": self.reachability_reason,
            "reachability_undetermined": self.reachability_undetermined,
            "alarms": [a.value for a in self.alarms],
            "notes": list(self.notes),
        }


@dataclass
class FallbackEvent:
    """One recorded hand-off from a component to whatever covered for it."""

    component: str
    covered_by: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"component": self.component, "covered_by": self.covered_by, "reason": self.reason}


class ContributionLedger:
    """Records what each component contributed over one engagement.

    Thread-safe: the concurrent Scan/Research/Exploit phase writes from several
    tasks at once, and a half-updated counter is a wrong number rather than a
    missing one.
    """

    def __init__(self, engagement_id: str = "") -> None:
        self.engagement_id = engagement_id
        self._records: dict[tuple[str, str], ComponentRecord] = {}
        self._fallbacks: list[FallbackEvent] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def _get(self, name: str, kind: ComponentKind) -> ComponentRecord:
        """Fetch or create a record. Caller holds the lock."""
        key = (kind.value, name)
        rec = self._records.get(key)
        if rec is None:
            rec = ComponentRecord(name=name, kind=kind)
            self._records[key] = rec
        return rec

    def declare(self, name: str, kind: ComponentKind, reachability: str = "") -> None:
        """Register a component the run *could* use, before it is invoked.

        Makes "declared but never invoked" observable. Without it, a capability
        that never resolves leaves no trace at all — and a component absent from
        the ledger reads exactly like one that was never built.

        Args:
            name: Component identifier, matching the name its invocation sites
                record under. A declaration under a different spelling produces
                two half-populated records, which is worse than none.
            kind: What kind of component it is.
            reachability: The ``ReachabilityKey`` value deciding whether this
                component's never-invoked state is a defect or a precondition
                that was absent. Evaluated later, at report time, by
                :meth:`resolve_reachability` — engagement state does not exist
                yet when this is called.
        """
        with self._lock:
            rec = self._get(name, kind)
            if reachability:
                rec.declared_reachability = reachability

    def resolve_reachability(self, state: Any) -> int:
        """Evaluate every declared predicate against completed engagement state.

        Called once, at REPORT time. Existence is knowable at engagement start;
        reachability is not — whether the target has a SQL surface is a question
        only Scan can answer, and the exploit plan does not exist when the
        declarations are made. Splitting the two is what lets a never-invoked
        component say which of the two things it is.

        Only components that were never invoked are evaluated: for one that ran,
        the ledger's ordinary accounting is the answer and a predicate would add
        nothing. A predicate that raises leaves the record un-evaluated
        (``reachable is None``), which produces no alarm — an observability layer
        must not manufacture a defect out of its own bug.

        **A predicate whose producer said nothing is not evaluated either.** Each
        predicate declares the ``ReachabilitySource`` its counters come from, and
        *state* declares which sources reported. A predicate reading a silent
        producer would compare against a default and answer ``False``, filing the
        component NOT APPLICABLE with a sentence about the target's surface — the
        exploit phase erroring once put that sentence beside all thirty
        methodology classes, in the client PDF. Those records get
        :meth:`ComponentRecord.set_reachability_undetermined` instead: no alarm,
        and no claim.

        Args:
            state: An
                :class:`~clinkz.observability.component_registry.EngagementReachability`.

        Returns:
            How many records were evaluated. Records left undetermined are not
            counted — nothing was answered for them.
        """
        from clinkz.observability.component_registry import PREDICATES, ReachabilityKey

        evaluated = 0
        with self._lock:
            records = list(self._records.values())
        for rec in records:
            if rec.invocations or not rec.declared_reachability:
                continue
            try:
                predicate = PREDICATES[ReachabilityKey(rec.declared_reachability)]
                silent = state.unreported_reason(predicate.source)
                if silent:
                    rec.set_reachability_undetermined(silent)
                    continue
                reachable = bool(predicate.holds(state, rec.name))
                rec.set_reachability(
                    reachable, "" if reachable else predicate.describe(state, rec.name)
                )
                evaluated += 1
            except Exception as exc:  # noqa: BLE001 — never raise from the data path
                logger.debug("Reachability predicate failed for %s: %s", rec.name, exc)
        return evaluated

    def record(
        self,
        *,
        name: str,
        kind: ComponentKind,
        items: int = 0,
        ok: bool = True,
        note: str = "",
        not_applicable: str = "",
    ) -> None:
        """Record one invocation and what it contributed.

        Args:
            name: Component identifier (``"ffuf"``, ``"exploit.plan_llm"``).
            kind: What kind of component it is.
            items: How many items this invocation contributed — URLs discovered,
                tasks planned, findings emitted. Zero is the value that matters.
            ok: Whether the invocation succeeded. A failure contributes nothing
                by definition, but is counted separately so an all-failed
                component is not reported as a silent one.
            note: Optional short context, deduplicated and capped.
            not_applicable: When non-empty, the caller is stating that this
                successful invocation contributed nothing because the
                precondition for contributing was ABSENT — no input of the kind
                this component reads — and the string is the reason. Ignored on
                a failure or when items were contributed, so the flag can never
                be used to talk a real contribution or a real failure away.
        """
        with self._lock:
            rec = self._get(name, kind)
            rec.invocations += 1
            if ok:
                rec.successes += 1
                contributed = max(0, int(items))
                rec.items_contributed += contributed
                if not_applicable and contributed == 0:
                    rec.not_applicable += 1
                    rec.add_not_applicable_reason(not_applicable)
            else:
                rec.failures += 1
            rec.add_note(note)

    def record_dead_seam(self, *, name: str, kind: ComponentKind, note: str) -> None:
        """Flag a component whose consumer/producer contract cannot be satisfied.

        Distinct from contributing zero: this one *cannot* contribute, whatever
        the target looks like. The ffuf seam was this for its whole existence.
        """
        with self._lock:
            rec = self._get(name, kind)
            rec.dead_seam = True
            rec.add_note(note)

    def record_fallback(self, *, component: str, covered_by: str, reason: str = "") -> None:
        """Record that something covered for *component*.

        The fallback is not the defect — it is the mechanism that made three
        defects invisible. Recording it is what turns "the run produced an
        answer" into "the run produced an answer, and here is who actually
        produced it".
        """
        with self._lock:
            self._fallbacks.append(
                FallbackEvent(component=component, covered_by=covered_by, reason=reason)
            )
            for (kind_value, name), rec in self._records.items():
                if name == component:
                    rec.fallback_activations += 1
                    rec.add_note(
                        f"covered by {covered_by}: {reason}"
                        if reason
                        else f"covered by {covered_by}"
                    )
                    break
            else:
                rec = self._get(component, ComponentKind.TOOL)
                rec.fallback_activations += 1
                rec.add_note(
                    f"covered by {covered_by}: {reason}" if reason else f"covered by {covered_by}"
                )

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    def records(self) -> list[ComponentRecord]:
        """Every record, ordered by kind then name."""
        with self._lock:
            return sorted(self._records.values(), key=lambda r: (r.kind.value, r.name))

    def alarming(self) -> list[ComponentRecord]:
        """Records tripping at least one alarm, most severe first."""
        order = {
            LedgerAlarm.DEAD_SEAM: 0,
            LedgerAlarm.ALL_FAILED: 1,
            LedgerAlarm.SILENT: 2,
            LedgerAlarm.BUILT_BUT_NOT_RUN: 3,
            LedgerAlarm.FALLBACK_ACTIVATED: 4,
        }
        alarming = [r for r in self.records() if r.alarms]
        return sorted(alarming, key=lambda r: (order[r.alarms[0]], r.kind.value, r.name))

    def never_invoked(self) -> list[ComponentRecord]:
        """Components declared but never asked to do anything.

        Quieter than a silent component — nothing ran, so nothing degraded — but
        a capability the run never reached for is still worth naming, because a
        resolver that silently found no tool looks identical to one that did.

        Includes the ones whose predicate says they WERE reachable; those also
        carry :attr:`LedgerAlarm.BUILT_BUT_NOT_RUN` and appear in
        :meth:`alarming`, exactly as an alarming component appears in both
        ``components`` and ``alarms``. Containment, not a second population.
        """
        return [r for r in self.records() if r.invocations == 0 and not r.dead_seam]

    def unreachable(self) -> list[ComponentRecord]:
        """Never-invoked components whose predicate says the run could not reach them.

        The NOT-APPLICABLE half of a declared component's zero, and the reason it
        is safe to declare thirty vuln classes on every engagement: a class whose
        surface the target does not have is not a defect, and reporting it as one
        would fill the alarm section with noise on every run until nobody read
        it — the same argument ``correctly_empty`` already makes for components
        that ran.
        """
        return [
            r
            for r in self.records()
            if r.invocations == 0 and not r.dead_seam and r.reachable is False
        ]

    def reachability_undetermined(self) -> list[ComponentRecord]:
        """Never-invoked components whose predicate could not be evaluated at all.

        The producer the predicate reads delivered nothing — an exploit phase
        that errored, a planner that recorded no pass — so its counters carry
        defaults, not measurements. Neither of the other two answers is
        available: the component is not an alarm (nothing says the run could
        have reached it) and it is not NOT APPLICABLE either, because that
        verdict comes with a sentence about what this target does not expose and
        no such observation was made.

        Reported as its own state so the deliverable can say *reachability was
        not determined* instead of picking one of two answers it does not have.
        """
        return [
            r
            for r in self.records()
            if r.invocations == 0 and not r.dead_seam and r.reachability_undetermined
        ]

    def correctly_empty(self) -> list[ComponentRecord]:
        """Components that ran, found nothing, and were right to.

        Reported, never alarmed. The whole point is that these lines can be read
        and dismissed at a glance — with the reason attached — instead of
        occupying the alarm list on every run until nobody reads it.
        """
        return [r for r in self.records() if r.correctly_empty and not r.dead_seam]

    def to_dict(self) -> dict[str, Any]:
        """The ledger as it appears in ``report.json``.

        ``components`` is the POPULATION — one entry per tracked component, and
        the only place a component's numbers live. Every other key is a VIEW
        onto it, never a second population:

        * ``alarms`` — the alarming subset, re-serialized in full and re-ordered
          most-severe-first, because four consumers render a row straight from
          it (the Markdown table, ``d1_consistency_runner``, two benchmark
          drivers) and a name-only reference would push a join into each of
          them. A join that silently misses a key drops an alarm, which is a
          worse failure than a duplicated payload.
        * ``never_invoked`` / ``correctly_empty`` / ``unreachable`` /
          ``reachability_undetermined`` — references by name.

        So an alarming component appears TWICE in this dict, with identical
        content, and that is containment rather than double registration. It
        reads exactly like a duplicate: ``exploit.component_cve_match`` was
        reported as one on the first non-benchmark run, and both readings
        offered — a second ``record_contribution`` call, or a serialization bug
        — were wrong. The component has exactly one registration site.

        The distinction matters because it decides whether a consumer may sum.
        Nothing in the engine does: ``summary`` is computed from
        ``self._records``, not from these lists, and all four consumers iterate
        ``alarms`` for display. A consumer that ever unions ``components`` with
        ``alarms`` WOULD double-count every alarming component — invisible today
        only because every alarming component has contributed zero items by
        definition. ``test_alarms_are_a_subset_view_not_a_second_population``
        pins the containment so this stays a projection.
        """
        alarming = self.alarming()
        inapplicable = self.correctly_empty()
        return {
            "components": [r.to_dict() for r in self.records()],
            "alarms": [r.to_dict() for r in alarming],
            "fallbacks": [f.to_dict() for f in self._fallbacks],
            "never_invoked": [r.name for r in self.never_invoked()],
            # The NOT-APPLICABLE third of the declaration's three states: built,
            # never run, and the predicate says the engagement could not reach
            # it. Carried with the predicate's own sentence, so "this class did
            # not run" is never left as a bare name a reader has to interpret.
            "unreachable": [
                {
                    "component": r.name,
                    "kind": r.kind.value,
                    "predicate": r.declared_reachability,
                    "reason": r.reachability_reason,
                }
                for r in self.unreachable()
            ],
            # The FOURTH state, and the one whose absence let a phase that never
            # ran write target claims into the PDF. Held apart from
            # ``unreachable`` because they answer different questions: that one
            # says the engagement could not reach the component, this one says
            # nobody can tell, and only the first is a statement about the
            # target.
            "reachability_undetermined": [
                {
                    "component": r.name,
                    "kind": r.kind.value,
                    "predicate": r.declared_reachability,
                    "reason": r.reachability_undetermined,
                }
                for r in self.reachability_undetermined()
            ],
            "correctly_empty": [
                {"component": r.name, "reasons": list(r.not_applicable_reasons)}
                for r in inapplicable
            ],
            "summary": {
                "components_tracked": len(self._records),
                "components_alarming": len(alarming),
                "dead_seams": sum(1 for r in alarming if LedgerAlarm.DEAD_SEAM in r.alarms),
                "silent_components": sum(1 for r in alarming if LedgerAlarm.SILENT in r.alarms),
                "all_failed_components": sum(
                    1 for r in alarming if LedgerAlarm.ALL_FAILED in r.alarms
                ),
                "built_but_not_run_components": sum(
                    1 for r in alarming if LedgerAlarm.BUILT_BUT_NOT_RUN in r.alarms
                ),
                "unreachable_components": len(self.unreachable()),
                "reachability_undetermined_components": len(self.reachability_undetermined()),
                "correctly_empty_components": len(inapplicable),
                "fallback_activations": len(self._fallbacks),
            },
        }

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def log_summary(self, log: logging.Logger | None = None) -> None:
        """Write the end-of-run summary to the run log, loudly.

        "Loudly" is literal and load-bearing: a silent component logged at DEBUG
        is a silent component. Dead seams and silent components go out at
        WARNING so they survive the default log level an operator actually
        reads.
        """
        out = log or logger
        try:
            alarming = self.alarming()
            total = len(self._records)
            if not alarming:
                out.info(
                    "Component ledger: %d component(s) tracked, all contributed at least one item",
                    total,
                )
            else:
                out.warning(
                    "COMPONENT LEDGER: %d of %d component(s) contributed nothing "
                    "or were covered for",
                    len(alarming),
                    total,
                )
            for rec in alarming:
                for alarm in rec.alarms:
                    out.warning("  %s", _alarm_line(rec, alarm))
            for rec in self.correctly_empty():
                out.info(
                    "  NOT APPLICABLE %s (%s) — %d invocation(s) found nothing, correctly: %s",
                    rec.name,
                    rec.kind.value,
                    rec.invocations,
                    "; ".join(rec.not_applicable_reasons) or "precondition absent",
                )
            for rec in self.unreachable():
                out.info(
                    "  NOT REACHABLE  %s (%s) — %s",
                    rec.name,
                    rec.kind.value,
                    rec.reachability_reason or rec.declared_reachability,
                )
            for rec in self.reachability_undetermined():
                out.info(
                    "  NOT DETERMINED %s (%s) — %s",
                    rec.name,
                    rec.kind.value,
                    rec.reachability_undetermined,
                )
            for rec in self.never_invoked():
                if rec.reachable is not None or rec.reachability_undetermined:
                    continue  # already reported above, or alarming
                out.info(
                    "  NEVER INVOKED  %s (%s) — declared but the run never asked for it",
                    rec.name,
                    rec.kind.value,
                )
        except Exception as exc:  # noqa: BLE001 — the ledger must never abort a run
            out.debug("Component ledger summary failed: %s", exc)


def _alarm_line(rec: ComponentRecord, alarm: LedgerAlarm) -> str:
    """One human-readable alarm line, naming the defect rather than a code."""
    notes = f" [{'; '.join(rec.notes)}]" if rec.notes else ""
    if alarm is LedgerAlarm.DEAD_SEAM:
        return (
            f"DEAD SEAM      {rec.name} ({rec.kind.value}) — the consumer cannot read this "
            f"producer's output; the capability is structurally inert{notes}"
        )
    if alarm is LedgerAlarm.ALL_FAILED:
        return (
            f"ALL FAILED     {rec.name} ({rec.kind.value}) — {rec.invocations} invocation(s), "
            f"0 succeeded{notes}"
        )
    if alarm is LedgerAlarm.SILENT:
        return (
            f"CONTRIBUTED 0  {rec.name} ({rec.kind.value}) — {rec.invocations} invocation(s), "
            f"{rec.successes} succeeded, 0 items contributed{notes}"
        )
    if alarm is LedgerAlarm.BUILT_BUT_NOT_RUN:
        return (
            f"NEVER RAN     {rec.name} ({rec.kind.value}) — built, and this engagement "
            f"met the condition for reaching it ({rec.declared_reachability}), but it was "
            f"never invoked{notes}"
        )
    return (
        f"FALLBACK       {rec.name} ({rec.kind.value}) — covered for "
        f"{rec.fallback_activations} time(s){notes}"
    )


# ---------------------------------------------------------------------------
# Active ledger (process-global, absent by default)
# ---------------------------------------------------------------------------


_active_ledger: ContributionLedger | None = None
_active_lock = threading.Lock()


def set_active_ledger(ledger: ContributionLedger | None) -> None:
    """Install (or clear) the ledger the wired call sites report to.

    Called by the Orchestrator at engagement start and cleared at the end, so
    module state from one run cannot contaminate the next.
    """
    global _active_ledger
    with _active_lock:
        _active_ledger = ledger


def get_active_ledger() -> ContributionLedger | None:
    """Return the active ledger, or ``None`` when no engagement installed one."""
    return _active_ledger


# ---------------------------------------------------------------------------
# Call-site helpers — no-op when no ledger is installed
# ---------------------------------------------------------------------------


def record_contribution(
    *,
    name: str,
    kind: ComponentKind,
    items: int = 0,
    ok: bool = True,
    note: str = "",
    not_applicable: str = "",
) -> None:
    """Record one invocation on the active ledger, if there is one.

    ``not_applicable`` states that this successful invocation contributed
    nothing because its precondition was absent, and carries the reason. See
    :meth:`ContributionLedger.record`.
    """
    ledger = get_active_ledger()
    if ledger is None:
        return
    try:
        ledger.record(
            name=name,
            kind=kind,
            items=items,
            ok=ok,
            note=note,
            not_applicable=not_applicable,
        )
    except Exception as exc:  # noqa: BLE001 — never raise from the data path
        logger.debug("Ledger record failed for %s: %s", name, exc)


def record_dead_seam(*, name: str, kind: ComponentKind, note: str) -> None:
    """Flag a structurally unsatisfiable consumer/producer contract."""
    ledger = get_active_ledger()
    if ledger is None:
        return
    try:
        ledger.record_dead_seam(name=name, kind=kind, note=note)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Ledger dead-seam record failed for %s: %s", name, exc)


def record_fallback(*, component: str, covered_by: str, reason: str = "") -> None:
    """Record that *covered_by* covered for *component*."""
    ledger = get_active_ledger()
    if ledger is None:
        return
    try:
        ledger.record_fallback(component=component, covered_by=covered_by, reason=reason)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Ledger fallback record failed for %s: %s", component, exc)


def declare_component(*, name: str, kind: ComponentKind, reachability: str = "") -> None:
    """Register a component the run could use, before any invocation."""
    ledger = get_active_ledger()
    if ledger is None:
        return
    try:
        ledger.declare(name, kind, reachability=reachability)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Ledger declare failed for %s: %s", name, exc)
