"""Whether a run left evidence a later reader can re-derive its claims from.

``outputs/<id>/tool_invocations/`` is the only artifact that holds the full
request and the full response for every call the engine made. The report is a
set of conclusions; the invocation records are what those conclusions were drawn
FROM. So a run with no invocation records is a run whose every claim rests on the
report agreeing with itself.

The engagement that produced this module
----------------------------------------

``e4814440`` — cal.diy, ``TOOL_EXEC_MODE=local`` — holds **0 invocation records**
and **0 ``tool_call`` trace rows** against 46 discovered endpoints, a proven
authenticated session, and a full set of methodology dispatches. The cause was
one call site: ``ToolBase._emit_trace_records`` was reached only from
``_run_subprocess`` / ``_run_subprocess_stdin``, and in local mode the HTTP tool
serves every request in-process through aiohttp and spawns no subprocess. Nothing
failed. The directory was created, stayed empty, and an empty
``tool_invocations/`` is byte-identical to a run that made no calls.

That is the shape this codebase keeps meeting: an absence that reads as a clean
result. The per-request fix is to emit from the in-process path too. This module
is the **second witness** — the one that makes the absence legible if the fix is
ever regressed, removed, or bypassed by a transport nobody has written yet.

What it counts, and why two numbers
-----------------------------------

* **executions** — how many times a tool actually ran, counted at the seam that
  runs it, whatever transport it used.
* **invocations recorded** — how many of those left a full-fidelity record.

A single number cannot say what went wrong. ``executions == 0`` is a run that
dispatched nothing (a refusal, a reconnaissance-only profile) and is honestly
unauditable because there was nothing to audit. ``executions > 0`` with
``recorded == 0`` is the defect above: work happened and left no evidence. The
two are distinguishable only if both are carried.

The verdict is one-way, and it is INDETERMINATE rather than negative
--------------------------------------------------------------------

An unaudited run is not a run that found nothing and not a run that failed. It is
a run whose artifacts cannot support its own conclusions, which is exactly the
state ``baseline_eligible`` exists to exclude — the same shape as
:func:`~clinkz.llm.degradation.reconcile_with_model_stamp`, and reconciled at the
same two seams (build and render) so a stored bundle written before this existed
still renders honestly. It only ever tightens: this module can withdraw
eligibility, never grant it.

Absent by default, like the governor, the plan-alarm register and the component
ledger. A directly invoked tool, a replay or a driver installs no register, every
hook no-ops, and nothing about the call changes.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

#: The verdicts a run's auditability can take. Three, not two: "nothing ran" is
#: not the same claim as "things ran and were recorded", and neither is the same
#: as "things ran and were not".
AUDITABLE = "auditable"
NOTHING_DISPATCHED = "nothing_dispatched"
INDETERMINATE = "indeterminate"


@dataclass
class AuditRegister:
    """Per-run tally of tool executions against the records they left.

    Thread-safe: concurrent phases execute tools from different tasks.
    """

    _executions: int = 0
    _recorded: int = 0
    _by_mode: dict[str, int] = field(default_factory=dict)
    _by_transport: dict[str, int] = field(default_factory=dict)
    _unrecorded_tools: dict[str, int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_execution(
        self,
        *,
        tool: str,
        exec_mode: str,
        transport: str,
        recorded: bool,
    ) -> None:
        """Note that one tool execution happened, and whether it left a record.

        Args:
            tool: The tool's ``name``.
            exec_mode: ``settings.tool_exec_mode`` as it was for this call.
            transport: ``subprocess`` or ``in_process``.
            recorded: Whether a full-fidelity invocation record was written.

        Never raises — an observability hook on the data path that can fail the
        call is worse than the blindness it was added to fix.
        """
        try:
            with self._lock:
                self._executions += 1
                key = f"{exec_mode}/{transport}"
                self._by_mode[exec_mode] = self._by_mode.get(exec_mode, 0) + 1
                self._by_transport[key] = self._by_transport.get(key, 0) + 1
                if recorded:
                    self._recorded += 1
                else:
                    self._unrecorded_tools[tool] = self._unrecorded_tools.get(tool, 0) + 1
        except Exception as exc:  # noqa: BLE001 — auditing must never raise
            logger.warning("AuditRegister.record_execution failed: %s", exc)

    @property
    def executions(self) -> int:
        """How many tool executions this run made."""
        with self._lock:
            return self._executions

    @property
    def invocations_recorded(self) -> int:
        """How many of them left a full-fidelity invocation record."""
        with self._lock:
            return self._recorded

    @property
    def verdict(self) -> str:
        """One of :data:`AUDITABLE`, :data:`NOTHING_DISPATCHED`, :data:`INDETERMINATE`.

        ``INDETERMINATE`` on the whole of the hole, not only on its total
        collapse: a run that recorded SOME of its executions has a partial
        evidence base, and a reader who checks one claim against the records and
        finds it cannot be checked has learned the wrong thing about the run
        rather than about that claim.
        """
        with self._lock:
            if self._executions == 0:
                return NOTHING_DISPATCHED
            return AUDITABLE if self._recorded == self._executions else INDETERMINATE

    def summary(self) -> dict[str, Any]:
        """Render for ``report.json``.

        Present on a clean run too, for the reason every other disclosure here
        is: "every call this run made is on disk" is a claim the deliverable
        should make explicitly, and a section that appears only on failure cannot
        be told apart from one nobody wrote.
        """
        with self._lock:
            executions = self._executions
            recorded = self._recorded
            by_mode = dict(sorted(self._by_mode.items()))
            by_transport = dict(sorted(self._by_transport.items()))
            unrecorded = dict(sorted(self._unrecorded_tools.items()))
        verdict = self.verdict
        return {
            "verdict": verdict,
            "auditable": verdict == AUDITABLE,
            "tool_executions": executions,
            "invocations_recorded": recorded,
            "unrecorded_executions": max(0, executions - recorded),
            "executions_by_exec_mode": by_mode,
            "executions_by_transport": by_transport,
            "unrecorded_by_tool": unrecorded,
        }

    def reset(self) -> None:
        """Forget every execution. For process teardown and tests.

        **Not** a way to recover auditability: the register is per-run, and
        clearing it mid-run would erase the record of a hole rather than close
        it.
        """
        with self._lock:
            self._executions = 0
            self._recorded = 0
            self._by_mode.clear()
            self._by_transport.clear()
            self._unrecorded_tools.clear()


# ---------------------------------------------------------------------------
# The active register — absent by default
# ---------------------------------------------------------------------------

_active_register: AuditRegister | None = None


def set_active_audit_register(register: AuditRegister | None) -> None:
    """Install (or clear) the run's register.

    Args:
        register: The register, or ``None`` to detach.
    """
    global _active_register
    _active_register = register


def get_active_audit_register() -> AuditRegister | None:
    """The run's register, or ``None`` when nothing installed one."""
    return _active_register


def record_execution(*, tool: str, exec_mode: str, transport: str, recorded: bool) -> None:
    """Note one tool execution against the active register, if there is one.

    Never raises and never creates a register: a tool invoked outside an
    engagement — a unit test, a replay, a driver — has no report to carry it.
    """
    register = _active_register
    if register is None:
        return
    register.record_execution(
        tool=tool, exec_mode=exec_mode, transport=transport, recorded=recorded
    )


def audit_summary() -> dict[str, Any]:
    """The active register's summary, or the clean shape when none is installed."""
    register = _active_register
    if register is None:
        return AuditRegister().summary()
    return register.summary()


def reconcile_run_audit(
    degradation: dict[str, Any], run_audit: dict[str, Any] | None
) -> dict[str, Any]:
    """Withdraw baseline eligibility from a run whose calls left no evidence.

    Same contract as :func:`~clinkz.llm.degradation.reconcile_with_model_stamp`,
    for the same reason: two witnesses to one claim, applied at BOTH the build
    and render seams so a stored bundle renders the same verdict the build
    reached, and **only ever tightening** — an absent or clean audit summary is
    not evidence that a run IS eligible, so this never sets the flag true.

    A bundle written before ``run_audit`` existed carries none, and gets no
    tightening: its invocation directory is still on disk and still empty, which
    is where that question belongs. Inventing a verdict for it here would be
    this module guessing about a run it never observed.

    Args:
        degradation: A :meth:`~clinkz.llm.degradation.DegradationRegister.summary`
            shape, already reconciled against the model stamp or not.
        run_audit: An :meth:`AuditRegister.summary` shape, or ``None``.

    Returns:
        A new dict. The input is not mutated.
    """
    out = dict(degradation)
    if not run_audit:
        return out
    if run_audit.get("verdict") != INDETERMINATE:
        return out
    out["baseline_eligible"] = False
    out["run_audit_verdict"] = INDETERMINATE
    # Named, not folded into the routing count. "Routing substituted a provider"
    # and "this run's calls left no evidence" are different facts with different
    # fixes, and a reader who sees only a lowered flag will look for a fallback
    # that never happened.
    out["baseline_ineligible_reason"] = (
        f"{run_audit.get('unrecorded_executions', 0)} of "
        f"{run_audit.get('tool_executions', 0)} tool execution(s) left no invocation "
        "record, so the run's claims cannot be re-derived from its artifacts"
    )
    return out


__all__ = [
    "AUDITABLE",
    "INDETERMINATE",
    "NOTHING_DISPATCHED",
    "AuditRegister",
    "audit_summary",
    "get_active_audit_register",
    "reconcile_run_audit",
    "record_execution",
    "set_active_audit_register",
]
