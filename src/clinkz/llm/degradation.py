"""Provider degradation — what a fallback costs the run that took one.

Routing v2 makes Anthropic priority 1 for every call on every phase. This
module is the other half of that rule: a fallback is a **disqualifying event**,
not an invisible one.

Why this is not just a log line
-------------------------------

The last instance was found by reading traces after the fact. Gemini had served
6 exploit plans and 6 false-positive cross-checks across 9 engagements — the FP
cross-check being the *suppression* path, so the cheap tier had been deciding
which confirmed findings got demoted — and every one of those reports looked
exactly like a report it had not happened to. The fallback worked. That is the
problem: it produced an answer, the run completed, and nothing in the
deliverable distinguished it from a run served end to end by the model that was
asked for.

A substitution is not the only way routing degrades
---------------------------------------------------

``degraded`` was ``bool(self._events)`` and an event was written only when a
provider **substituted** for another. A chain that runs out substitutes nothing,
so it wrote nothing — and engagement ``2e21a200`` failed its recon, scan AND
exploit phases with ``All providers exhausted``, produced zero findings, and
reported ``provider_degraded: false, baseline_eligible: true``. The register was
answering "did a fallback happen" while the document was asking "may these
numbers be compared", and on a total outage those come apart completely: the
worst possible run reads as the cleanest.

Three things now degrade a run, and they are recorded as different KINDS because
they have different fixes:

* :attr:`DegradationKind.SUBSTITUTION` — a provider other than the primary
  answered. Someone else's model shaped the output.
* :attr:`DegradationKind.TERMINAL_EXCLUSION` — a provider hit a terminal account
  condition and was excluded for the rest of the run. Every later call in the
  engagement ran against a shorter chain than the one that was configured, and
  it is silent at each of those call sites.
* :attr:`DegradationKind.CHAIN_EXHAUSTED` — nobody answered. The phase got no
  LLM result at all and continued on whatever its no-answer path does, which is
  a smaller engagement wearing the same artifacts.

The last two are **absences**. They carry no served model because nothing served
them, which is exactly why they could not be expressed as a
:class:`ProviderFallback` and therefore were not expressed at all.

So a fallback now has two outcomes and no third:

* **baseline mode** — hard failure. A recorded baseline is only worth the
  comparison it supports, and a ladder served by two models is not a ladder.
  The evidence is not hypothetical: over 1,033 recorded phase-3 calls, the same
  prompt on a byte-identical header observation produced the version-disclosure
  entries 27% of the time under one model and 80% under another. A number
  produced half by one model and half by another is not a measurement of the
  target.
* **client mode** — the run completes, because a client engagement should not
  die because a provider had a bad minute. The report is stamped
  ``provider_degraded`` naming every call site and both models, and the run is
  marked **permanently ineligible as a baseline**.

Ineligibility is one-way on purpose. There is no code path that clears it: the
degraded call already happened and its output is already inside the findings,
so a later clean call cannot un-shape it. :meth:`DegradationRegister.reset` is
for process teardown between runs and tests, never for recovery.

Absent by default, like the governor and the ledger: a directly invoked
methodology, a replay or a driver installs no register and every hook no-ops,
so the black-box floor is byte-identical.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)

#: The provider name a trace records when nothing served a call. Written by
#: :class:`~clinkz.llm.fallback.ResilientLLMClient` as
#: ``self._last_used_provider or "exhausted"``, so it reaches ``model_stamp``
#: and therefore ``report.json`` — which is what lets a STORED bundle be
#: reconciled after the fact, with no register in the process.
EXHAUSTED_PROVIDER: str = "exhausted"


class DegradationKind(StrEnum):
    """How routing degraded. Three kinds, three different fixes.

    Attributes:
        SUBSTITUTION: A provider other than the primary answered.
        TERMINAL_EXCLUSION: A provider was excluded for the remainder of the run
            after a terminal account condition. Every later call ran against a
            shorter chain than the configured one.
        CHAIN_EXHAUSTED: Nobody answered. The phase got no LLM result at all.
    """

    SUBSTITUTION = "substitution"
    TERMINAL_EXCLUSION = "terminal_exclusion"
    CHAIN_EXHAUSTED = "chain_exhausted"


@dataclass(frozen=True)
class ProviderFallback:
    """One call that a provider other than the primary served.

    Attributes:
        agent_role: The role whose call it was (``exploit``, ``scan``, ...).
        method: The ``LLMClient`` method — ``generate_text``, ``reason``,
            ``research``. Together with *agent_role* this is the "call site"
            the report has to name: "exploit fell back" is not actionable,
            "exploit.generate_text fell back" points at the plan.
        asked_provider: The provider the chain led with.
        asked_model: The model that provider would have used.
        served_provider: The provider that actually answered.
        served_model: The model that actually answered. It is this one that
            shaped the output.
        reason: The error class that caused the rotation, when known.
        decision_bearing: Whether this role's answer becomes a conclusion of
            the engagement rather than an observation a later oracle re-derives.
    """

    agent_role: str
    method: str
    asked_provider: str
    asked_model: str
    served_provider: str
    served_model: str
    reason: str = ""
    decision_bearing: bool = False

    @property
    def call_site(self) -> str:
        """``role.method`` — what the report names."""
        return f"{self.agent_role}.{self.method}"

    def to_dict(self) -> dict[str, Any]:
        """Render for ``report.json``."""
        return {
            "call_site": self.call_site,
            "agent_role": self.agent_role,
            "method": self.method,
            "asked_provider": self.asked_provider,
            "asked_model": self.asked_model,
            "served_provider": self.served_provider,
            "served_model": self.served_model,
            "reason": self.reason,
            "decision_bearing": self.decision_bearing,
        }

    def describe(self) -> str:
        """One line for a log or a report row."""
        served = f"{self.served_provider}/{self.served_model}"
        asked = f"{self.asked_provider}/{self.asked_model}"
        tail = f" ({self.reason})" if self.reason else ""
        marker = " [decision-bearing]" if self.decision_bearing else ""
        return f"{self.call_site}: asked {asked}, served by {served}{tail}{marker}"


@dataclass(frozen=True)
class ProviderAbsence:
    """One call that NOTHING served, or one provider lost for the rest of the run.

    The half a :class:`ProviderFallback` structurally cannot express. A fallback
    names the provider and model that answered; an absence exists precisely
    because there is no such pair, so recording it as a fallback would require
    inventing one.

    Attributes:
        agent_role: The role whose call it was.
        method: The ``LLMClient`` method. With *agent_role* this is the call
            site — "recon fell through the whole chain" points at a phase, "recon
            fell through" does not.
        kind: :attr:`DegradationKind.TERMINAL_EXCLUSION` or
            :attr:`DegradationKind.CHAIN_EXHAUSTED`. Never ``SUBSTITUTION`` —
            that one has a served model and is a :class:`ProviderFallback`.
        provider: The excluded provider for a terminal exclusion. Empty for an
            exhausted chain, where the subject is the chain rather than any one
            member.
        chain: The chain that was tried, for an exhausted one.
        reason: The error class that caused it, when known.
        decision_bearing: Whether this role's answer becomes a conclusion of the
            engagement rather than an observation a later oracle re-derives.
    """

    agent_role: str
    method: str
    kind: DegradationKind
    provider: str = ""
    chain: tuple[str, ...] = ()
    reason: str = ""
    decision_bearing: bool = False

    @property
    def call_site(self) -> str:
        """``role.method`` — what the report names."""
        return f"{self.agent_role}.{self.method}"

    def to_dict(self) -> dict[str, Any]:
        """Render for ``report.json``."""
        return {
            "call_site": self.call_site,
            "agent_role": self.agent_role,
            "method": self.method,
            "kind": self.kind.value,
            "provider": self.provider,
            "chain": list(self.chain),
            "reason": self.reason,
            "decision_bearing": self.decision_bearing,
        }

    def describe(self) -> str:
        """One line for a log or a report row."""
        subject = self.provider or f"chain {list(self.chain)}"
        tail = f" ({self.reason})" if self.reason else ""
        marker = " [decision-bearing]" if self.decision_bearing else ""
        return f"{self.call_site}: {self.kind.value} — {subject}{tail}{marker}"


@dataclass
class DegradationRegister:
    """Every way routing degraded this run, and the eligibility it cost.

    Two lists rather than one, because a substitution and an absence carry
    different fields: a fallback has a served provider and model, an absence has
    neither and exists because of that. Merging them would mean writing
    ``served_model=""`` and calling it a fallback, which is the shape that hid
    the outage in the first place.

    Thread-safe: phases run concurrently and each has its own client.
    """

    _events: list[ProviderFallback] = field(default_factory=list)
    _absences: list[ProviderAbsence] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, event: ProviderFallback) -> None:
        """Record one fallback. Always loud — this is never a debug line."""
        with self._lock:
            self._events.append(event)
        logger.warning(
            "PROVIDER DEGRADED — %s. This run is permanently ineligible as a baseline.",
            event.describe(),
        )

    def record_absence(self, absence: ProviderAbsence) -> None:
        """Record one absence — a chain that ran out, or a provider lost.

        Loud for the same reason and at the same level: an absence is strictly
        worse for comparability than a substitution. A substituted answer is at
        least an answer.
        """
        with self._lock:
            self._absences.append(absence)
        logger.warning(
            "PROVIDER DEGRADED (absence) — %s. Nothing served this call; this run is "
            "permanently ineligible as a baseline.",
            absence.describe(),
        )

    def events(self) -> list[ProviderFallback]:
        """Every recorded fallback, in the order it happened."""
        with self._lock:
            return list(self._events)

    def absences(self) -> list[ProviderAbsence]:
        """Every recorded absence, in the order it happened."""
        with self._lock:
            return list(self._absences)

    @property
    def degraded(self) -> bool:
        """Whether routing delivered anything other than what was asked for.

        True on a substitution, on a terminal exclusion, AND on an exhausted
        chain. It used to be ``bool(self._events)`` — substitutions only — so a
        run whose every phase failed reported no degradation at all.
        """
        with self._lock:
            return bool(self._events or self._absences)

    @property
    def baseline_eligible(self) -> bool:
        """Whether this run may be used as a baseline.

        One-way, and it FOLLOWS :attr:`degraded` rather than being computed from
        the fallback list separately — two expressions of one fact drift, and
        this pair drifted.
        """
        return not self.degraded

    def decision_bearing_events(self) -> list[ProviderFallback]:
        """The subset whose answers became conclusions rather than observations."""
        return [event for event in self.events() if event.decision_bearing]

    def decision_bearing_absences(self) -> list[ProviderAbsence]:
        """The absences on a role whose answer becomes a conclusion."""
        return [absence for absence in self.absences() if absence.decision_bearing]

    def summary(self) -> dict[str, Any]:
        """Render for ``report.json``.

        Present even when nothing degraded: "no fallback occurred" is a claim
        the deliverable should make explicitly. A section that appears only on
        failure cannot be distinguished from a section nobody wrote.
        """
        events = self.events()
        absences = self.absences()
        served_by: dict[str, int] = {}
        for event in events:
            key = f"{event.served_provider}/{event.served_model}"
            served_by[key] = served_by.get(key, 0) + 1
        absence_kinds: dict[str, int] = {}
        for absence in absences:
            absence_kinds[absence.kind.value] = absence_kinds.get(absence.kind.value, 0) + 1
        return {
            "provider_degraded": bool(events or absences),
            "baseline_eligible": not (events or absences),
            "fallback_count": len(events),
            "absence_count": len(absences),
            "absence_kinds": absence_kinds,
            "decision_bearing_fallback_count": len(self.decision_bearing_events()),
            "decision_bearing_absence_count": len(self.decision_bearing_absences()),
            "call_sites": sorted(
                {event.call_site for event in events} | {a.call_site for a in absences}
            ),
            "served_by": served_by,
            "events": [event.to_dict() for event in events],
            "absences": [absence.to_dict() for absence in absences],
        }

    def reset(self) -> None:
        """Forget every event.

        For process teardown and tests. **Not** a way to recover eligibility:
        the register is per-run, and clearing it mid-run would erase the record
        of a degradation whose output is already in the findings.
        """
        with self._lock:
            self._events.clear()
            self._absences.clear()


# ---------------------------------------------------------------------------
# The active register — absent by default
# ---------------------------------------------------------------------------

_active_register: DegradationRegister | None = None


def set_active_degradation_register(register: DegradationRegister | None) -> None:
    """Install (or clear) the run's register.

    Args:
        register: The register, or ``None`` to detach. Arranged exactly like
            :func:`clinkz.safety.governor.get_active_governor`: absent by
            default so a directly invoked methodology, a replay or a driver is
            byte-identical to before this existed.
    """
    global _active_register
    _active_register = register


def get_active_degradation_register() -> DegradationRegister | None:
    """The run's register, or ``None`` when nothing installed one."""
    return _active_register


def record_provider_fallback(event: ProviderFallback) -> None:
    """Record a fallback against the active register, if there is one.

    Never raises and never creates a register: a call made outside an
    engagement has no run to disqualify.
    """
    register = _active_register
    if register is None:
        return
    register.record(event)


def record_provider_absence(absence: ProviderAbsence) -> None:
    """Record an absence against the active register, if there is one.

    Never raises and never creates a register: a call made outside an engagement
    has no run to disqualify.
    """
    register = _active_register
    if register is None:
        return
    register.record_absence(absence)


def degradation_summary() -> dict[str, Any]:
    """The active register's summary, or the clean shape when none is installed.

    The clean shape rather than ``{}`` so the report always carries the claim.
    A run with no register made no LLM calls through the resilient client, and
    "nothing degraded" is true of it.
    """
    register = _active_register
    if register is None:
        return DegradationRegister().summary()
    return register.summary()


def exhausted_stages(model_stamp: list[dict[str, Any]]) -> list[str]:
    """Stages whose model stamp says nothing served them.

    The trace writes ``self._last_used_provider or "exhausted"`` when a dispatch
    raises, so an outage leaves its mark in ``model_stamp`` whether or not a
    register was installed to catch it. That makes the stamp a SECOND,
    independent witness — and the only one available offline, over a bundle
    whose process ended long ago.

    Args:
        model_stamp: ``report.model_stamp`` — ``[{"stage", "provider", ...}]``.

    Returns:
        Sorted, de-duplicated stage names.
    """
    return sorted(
        {
            str(entry.get("stage") or "")
            for entry in model_stamp
            if isinstance(entry, dict) and entry.get("provider") == EXHAUSTED_PROVIDER
        }
        - {""}
    )


def stamp_exhaustion(report: Mapping[str, Any]) -> list[str] | None:
    """Which stages nothing served, or ``None`` when the bundle makes no claim.

    :func:`exhausted_stages` answers a question about a stamp that EXISTS. This
    answers the question a stored bundle actually poses, which is one step
    earlier: *does this bundle say anything about which stages were served?*
    The two are not the same, and the difference is the whole guard —
    ``exhausted_stages(report.get("model_stamp") or [])`` returns ``[]`` for a
    bundle with no stamp, which is byte-identical to a run every stage of which
    was served. An absent stamp is INDETERMINATE, never clean.

    That distinction is load-bearing rather than pedantic, because the absence
    is what the failure this guards against PRODUCES. A run that dies to a
    depleted balance may never write its stamp at all; the two guards standing
    between a credit lapse and another void batch — the benchmark floor's stamp
    refusal and the variance envelope's per-run abort — both read the coalesced
    ``[]`` and both passed it. The guard's own reading defeated the guard.

    An EMPTY stamp is indeterminate for the same reason it is not a claim: the
    stamp is written from the run's own ``llm_call`` trace events, and every
    phase of a real engagement makes at least one. No entries means no trace,
    not "every stage was served".

    Args:
        report: A parsed ``report_<id>.json``. The REPORT, deliberately, not the
            stamp: a caller that has already coalesced ``model_stamp`` to a list
            has destroyed the absence this function exists to see.

    Returns:
        Sorted, de-duplicated stage names that nothing served — possibly empty,
        which IS a claim — or ``None`` when the bundle carries no usable stamp.
    """
    stamp = report.get("model_stamp")
    if not isinstance(stamp, list) or not stamp:
        return None
    return exhausted_stages(stamp)


def reconcile_with_model_stamp(
    summary: dict[str, Any], model_stamp: list[dict[str, Any]]
) -> dict[str, Any]:
    """Refuse a clean routing claim that the run's own model stamp contradicts.

    Two witnesses to one fact, and they disagreed. ``model_stamp`` is written
    from the trace at the moment a dispatch raises; the register is written only
    where a substitution happened. On engagement ``2e21a200`` the stamp recorded
    ``provider: "exhausted"`` for recon, scan and exploit while the register said
    ``provider_degraded: false`` — and the report rendered the register's half,
    which is the half a reader sees. A document that contradicts itself is bad;
    a document that contradicts itself and shows only the reassuring side is
    worse.

    Applied in both directions of use: when the report is BUILT (so
    ``report.json`` carries the reconciled verdict) and again when it is
    RENDERED (so a stored bundle written before this existed still renders
    honestly). One function, two call sites — a renderer that re-derived the
    rule would be a third witness with its own drift.

    Only ever tightens. ``provider_degraded`` can go false→true and
    ``baseline_eligible`` true→false, never the reverse: the register's positive
    findings are observations, and an empty stamp is not evidence against one.

    Args:
        summary: A :meth:`DegradationRegister.summary` shape.
        model_stamp: ``report.model_stamp``.

    Returns:
        A new dict. The input is not mutated.
    """
    stages = exhausted_stages(model_stamp)
    reconciled = dict(summary)
    reconciled["exhausted_stages"] = stages
    if not stages:
        return reconciled
    reconciled["provider_degraded"] = True
    reconciled["baseline_eligible"] = False
    if not reconciled.get("absence_count"):
        # The register missed it — this is the pre-fix shape, or a phase whose
        # client had no register installed. Say so rather than reporting an
        # absence count of zero beside a degraded verdict, which reads as a
        # rendering bug and invites someone to "fix" it back.
        reconciled["absence_source"] = "model_stamp"
    return reconciled


__all__ = [
    "EXHAUSTED_PROVIDER",
    "DegradationKind",
    "DegradationRegister",
    "ProviderAbsence",
    "ProviderFallback",
    "degradation_summary",
    "exhausted_stages",
    "get_active_degradation_register",
    "reconcile_with_model_stamp",
    "record_provider_absence",
    "record_provider_fallback",
    "set_active_degradation_register",
    "stamp_exhaustion",
]
