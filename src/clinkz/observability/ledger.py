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
    notes: list[str] = field(default_factory=list)

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
        if self.invocations > 0 and self.successes == 0:
            out.append(LedgerAlarm.ALL_FAILED)
        elif self.invocations > 0 and self.items_contributed == 0:
            # Succeeded at least once and produced nothing. The defect shape.
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

    def declare(self, name: str, kind: ComponentKind) -> None:
        """Register a component the run *could* use, before it is invoked.

        Makes "declared but never invoked" observable. Without it, a capability
        that never resolves leaves no trace at all — and a component absent from
        the ledger reads exactly like one that was never built.
        """
        with self._lock:
            self._get(name, kind)

    def record(
        self,
        *,
        name: str,
        kind: ComponentKind,
        items: int = 0,
        ok: bool = True,
        note: str = "",
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
        """
        with self._lock:
            rec = self._get(name, kind)
            rec.invocations += 1
            if ok:
                rec.successes += 1
                rec.items_contributed += max(0, int(items))
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
            LedgerAlarm.FALLBACK_ACTIVATED: 3,
        }
        alarming = [r for r in self.records() if r.alarms]
        return sorted(alarming, key=lambda r: (order[r.alarms[0]], r.kind.value, r.name))

    def never_invoked(self) -> list[ComponentRecord]:
        """Components declared but never asked to do anything.

        Quieter than a silent component — nothing ran, so nothing degraded — but
        a capability the run never reached for is still worth naming, because a
        resolver that silently found no tool looks identical to one that did.
        """
        return [r for r in self.records() if r.invocations == 0 and not r.dead_seam]

    def to_dict(self) -> dict[str, Any]:
        """The ledger as it appears in ``report.json``."""
        alarming = self.alarming()
        return {
            "components": [r.to_dict() for r in self.records()],
            "alarms": [r.to_dict() for r in alarming],
            "fallbacks": [f.to_dict() for f in self._fallbacks],
            "never_invoked": [r.name for r in self.never_invoked()],
            "summary": {
                "components_tracked": len(self._records),
                "components_alarming": len(alarming),
                "dead_seams": sum(1 for r in alarming if LedgerAlarm.DEAD_SEAM in r.alarms),
                "silent_components": sum(1 for r in alarming if LedgerAlarm.SILENT in r.alarms),
                "all_failed_components": sum(
                    1 for r in alarming if LedgerAlarm.ALL_FAILED in r.alarms
                ),
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
            for rec in self.never_invoked():
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
) -> None:
    """Record one invocation on the active ledger, if there is one."""
    ledger = get_active_ledger()
    if ledger is None:
        return
    try:
        ledger.record(name=name, kind=kind, items=items, ok=ok, note=note)
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


def declare_component(*, name: str, kind: ComponentKind) -> None:
    """Register a component the run could use, before any invocation."""
    ledger = get_active_ledger()
    if ledger is None:
        return
    try:
        ledger.declare(name, kind)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Ledger declare failed for %s: %s", name, exc)
