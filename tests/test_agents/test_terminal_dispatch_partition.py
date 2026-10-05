"""A class that leaves the target changed must be declared, and must run last.

Two halves, and they fail in opposite ways.

**The partition** is the guard-domain law: the domain is
:data:`~clinkz.agents.exploit.DISPATCHABLE_TEST_METHODS`, computed from the
table the dispatcher itself reads, and every member must appear in exactly one
of ``TERMINAL_DISPATCH_CLASSES`` / ``TRANSIENT_DISPATCH_CLASSES`` with a
substantive reason. A class in neither is a red build, because "nobody
classified it" and "it leaves nothing behind" are different facts and only one
of them is safe to dispatch early.

**The ordering** is asserted where it is acted on. It holds by construction
today — the rotation only reaches a terminal class once no transient task is
left — and that is exactly why the runtime check exists: a scheduler change that
interleaved differently would break the property silently, and the failure is
invisible in the artifacts. Every class dispatched after a terminal one grades
its arms against a target this run has already altered, and the results look
exactly like results.

So both are tested, and separately. The rotation test measures the property the
guard protects; the guard test forces the violation the rotation currently
cannot produce, because the rotation is the half that might change.
"""

from __future__ import annotations

import logging

import pytest

from clinkz.agents import exploit as exploit_module
from clinkz.agents._control_arm import ConfirmingArm
from clinkz.agents.exploit import (
    DISPATCHABLE_TEST_METHODS,
    TERMINAL_DISPATCH_CLASSES,
    TRANSIENT_DISPATCH_CLASSES,
    ExploitAgent,
    TerminalDispatchOrderError,
    assert_terminal_dispatch_order,
    terminal_dispatch_rank,
    terminal_drain_order,
)
from clinkz.models.finding import ExploitPlan, ExploitTask

_MIN_REASON_WORDS = 6


class TestThePartitionIsComplete:
    """Domain computed, classification declared — both directions asserted."""

    def test_every_dispatchable_class_is_classified(self) -> None:
        declared = set(TERMINAL_DISPATCH_CLASSES) | set(TRANSIENT_DISPATCH_CLASSES)
        missing = DISPATCHABLE_TEST_METHODS - declared
        assert not missing, (
            f"{sorted(missing)} can be dispatched and no table says whether their effect "
            "outlives the run. An unclassified class is dispatched as transient, which is "
            "the unsafe default: if it mutates the target, every class after it measures a "
            "different application"
        )

    def test_no_table_entry_outlived_the_class_it_described(self) -> None:
        declared = set(TERMINAL_DISPATCH_CLASSES) | set(TRANSIENT_DISPATCH_CLASSES)
        stale = declared - DISPATCHABLE_TEST_METHODS
        assert not stale, f"{sorted(stale)} are declared here and are no longer dispatchable"

    def test_the_two_tables_do_not_overlap(self) -> None:
        both = set(TERMINAL_DISPATCH_CLASSES) & set(TRANSIENT_DISPATCH_CLASSES)
        assert not both, f"{sorted(both)} are declared both terminal and transient"

    @pytest.mark.parametrize(
        "table",
        [TERMINAL_DISPATCH_CLASSES, TRANSIENT_DISPATCH_CLASSES],
        ids=["terminal", "transient"],
    )
    def test_every_entry_carries_a_substantive_reason(self, table: dict[str, str]) -> None:
        """A one-word reason is a box ticked, not a decision made."""
        thin = {k: v for k, v in table.items() if len(v.split()) < _MIN_REASON_WORDS}
        assert not thin, f"reasons too thin to have been reviewed: {sorted(thin)}"


class TestTheGuardStopsTheRun:
    """Not a warning. A run that continues past this produces confident nonsense."""

    def test_a_transient_class_after_a_terminal_one_raises(self) -> None:
        terminal = next(iter(TERMINAL_DISPATCH_CLASSES))
        with pytest.raises(TerminalDispatchOrderError) as raised:
            assert_terminal_dispatch_order("_test_sqli", {terminal})
        message = str(raised.value)
        assert "_test_sqli" in message
        assert terminal in message

    def test_a_terminal_class_may_continue_its_own_queue(self) -> None:
        """The ordinary tail of a run: one terminal class working through its tasks."""
        terminal = next(iter(TERMINAL_DISPATCH_CLASSES))
        assert_terminal_dispatch_order(terminal, {terminal})

    def test_the_declared_terminal_order_is_permitted(self) -> None:
        """Later-declared after earlier-declared is exactly what the rotation does."""
        declared = sorted(TERMINAL_DISPATCH_CLASSES, key=terminal_dispatch_rank)
        for index, method in enumerate(declared):
            assert_terminal_dispatch_order(method, set(declared[:index]))

    @pytest.mark.skipif(
        len(TERMINAL_DISPATCH_CLASSES) < 2,
        reason="the ordering among terminal classes only exists once there are two",
    )
    def test_a_terminal_class_after_a_later_declared_one_raises(self) -> None:
        """Terminal-after-terminal is NOT free once there are two of them.

        The old rule permitted any terminal class after any other, which was
        correct while there was one and became a hole the moment there were two.
        The order is fixed on interference: a write crossing does not change how
        the target process parses later writes, and a prototype write does.
        """
        declared = sorted(TERMINAL_DISPATCH_CLASSES, key=terminal_dispatch_rank)
        earlier, later = declared[0], declared[1]
        with pytest.raises(TerminalDispatchOrderError) as raised:
            assert_terminal_dispatch_order(earlier, {later})
        message = str(raised.value)
        assert earlier in message
        assert later in message

    def test_nothing_dispatched_yet_permits_anything(self) -> None:
        assert_terminal_dispatch_order("_test_sqli", set())


class TestAnUndispatchableControlDoesNotSendThePayload:
    """The seam refuses to make an irreversible change it can never use.

    ``ControlVerdict.satisfied`` requires ``dispatched``, so a control that could
    not be SENT has already killed the finding. In the ordinary arm order that
    costs nothing — the confirming arm has already run. In the control-first
    order it would mean dispatching the payload anyway, and this seam exists
    precisely for payloads whose effect outlives the request, so "anyway" is an
    irreversible change to the client's system that no finding can come out of.
    """

    @pytest.mark.asyncio
    async def test_the_confirming_arm_is_not_run(self, monkeypatch: pytest.MonkeyPatch) -> None:
        agent = ExploitAgent.__new__(ExploitAgent)
        agent._logger = logging.getLogger("test.exploit.control_first")
        agent._control_arms = {}
        agent._unproven_exploit_leads = []
        agent._control_arm_kills = 0
        agent._control_arm_kill_disclosures = 0
        monkeypatch.setattr(agent, "_trace_methodology_phase", lambda **kw: None)
        monkeypatch.setattr(agent, "_strip_empty_fragment", lambda url: url)
        monkeypatch.setattr(agent, "_truncate", lambda text, n: text[:n])

        ran: list[str] = []

        async def _control_that_cannot_be_sent(decoy: str) -> bool:
            raise OSError("connection refused")

        async def _confirming() -> ConfirmingArm:
            ran.append("payload")
            return ConfirmingArm(payload="{}", observation="something", confirmed=True)

        verdict, arm = await agent._run_control_arm_first(
            skill="prototype_pollution",
            test_method="_test_prototype_pollution",
            technique="CWE-1321",
            endpoint="http://t/api/v2/profile",
            parameter="__proto__.x",
            control_label="an ordinary key in place of the prototype-reaching one",
            oracle_confirms=_control_that_cannot_be_sent,
            confirming_arm=_confirming,
        )

        assert ran == [], "the payload was dispatched after a control that never went out"
        assert verdict.dispatched is False
        assert verdict.satisfied is False
        assert arm.payload == ""
        # And the kill is still disclosed — silence would read as a clean endpoint.
        assert agent._unproven_exploit_leads, "an un-dispatched arm disclosed nothing"


class TestTheRotationPutsTerminalClassesLast:
    """The property the guard protects, measured on the real dispatcher."""

    @staticmethod
    def _agent() -> ExploitAgent:
        agent = ExploitAgent.__new__(ExploitAgent)
        agent._logger = logging.getLogger("test.exploit.terminal")
        agent._tests_run = 0
        agent._stopped_early = False
        agent._category_max_findings = 5
        agent._category_time_budget = 90.0
        return agent

    @pytest.mark.asyncio
    async def test_a_terminal_class_runs_only_once_nothing_else_is_left(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        agent = self._agent()
        terminal = next(iter(TERMINAL_DISPATCH_CLASSES))
        dispatched: list[str] = []

        async def _execute(task: ExploitTask, cache: dict) -> list:
            dispatched.append(task.test_method)
            return []

        monkeypatch.setattr(agent, "_execute_task", _execute)
        monkeypatch.setattr(agent, "_should_stop_dispatching", lambda: False)
        monkeypatch.setattr(agent, "_trace_dispatch_ordinal", lambda task, ordinal: None)

        plan = ExploitPlan(
            tasks=[
                # Terminal FIRST in plan order: the rotation must move it anyway,
                # because plan order is not what decides dispatch order.
                ExploitTask(test_method=terminal, endpoint_url="http://t/api", tier=1),
                ExploitTask(test_method="_test_sqli", endpoint_url="http://t/p?id=1", tier=1),
                ExploitTask(test_method="_test_idor", endpoint_url="http://t/p?id=2", tier=1),
                ExploitTask(test_method=terminal, endpoint_url="http://t/api2", tier=1),
                ExploitTask(test_method="_test_sqli", endpoint_url="http://t/p?id=3", tier=1),
            ]
        )
        await agent._step_execute_exploits(plan, None)

        assert dispatched[-2:] == [terminal, terminal], dispatched
        assert terminal not in dispatched[:-2], dispatched


class TestAWrongRotationStopsTheRun:
    """The guard OBSERVED refusing a real run, not just a direct call.

    The property holds by construction today: the rotation yields terminal
    classes in declaration order. That is precisely why the guard reads the
    declaration ITSELF rather than the helper the rotation sorts by — a guard
    that consulted the same derived value would agree with the rotation by
    construction and could never catch it being wrong.

    So the failure is forced the only way a real one could happen: the
    dispatcher's ordering helper is replaced, standing in for the scheduler
    change the guard exists to survive. A guard not seen refusing is not a guard.
    """

    @pytest.mark.skipif(
        len(TERMINAL_DISPATCH_CLASSES) < 2,
        reason="the ordering among terminal classes only exists once there are two",
    )
    @pytest.mark.asyncio
    async def test_terminals_dispatched_backwards_stop_the_run(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        declared = sorted(TERMINAL_DISPATCH_CLASSES, key=terminal_dispatch_rank)
        earlier, later = declared[0], declared[1]

        agent = ExploitAgent.__new__(ExploitAgent)
        agent._logger = logging.getLogger("test.exploit.terminal.rotation")
        agent._tests_run = 0
        agent._stopped_early = False
        agent._category_max_findings = 5
        agent._category_time_budget = 90.0

        dispatched: list[str] = []

        async def _execute(task: ExploitTask, cache: dict) -> list:
            dispatched.append(task.test_method)
            return []

        monkeypatch.setattr(agent, "_execute_task", _execute)
        monkeypatch.setattr(agent, "_should_stop_dispatching", lambda: False)
        monkeypatch.setattr(agent, "_trace_dispatch_ordinal", lambda task, ordinal: None)
        # A scheduler that orders the terminal tail the other way round.
        monkeypatch.setattr(
            exploit_module,
            "terminal_drain_order",
            lambda methods: sorted(methods, key=terminal_dispatch_rank, reverse=True)[:1],
        )

        plan = ExploitPlan(
            tasks=[
                ExploitTask(test_method=earlier, endpoint_url="http://t/api/a", tier=1),
                ExploitTask(test_method=later, endpoint_url="http://t/api/b", tier=1),
            ]
        )
        with pytest.raises(TerminalDispatchOrderError) as raised:
            await agent._step_execute_exploits(plan, None)

        assert dispatched == [later], (
            "the later-declared terminal class must have gone out first for this test "
            f"to be measuring the inversion — dispatched {dispatched}"
        )
        assert earlier in str(raised.value)
        assert later in str(raised.value)


class TestTerminalsDrainSequentially:
    """Rotation and a fixed terminal order are incompatible by construction.

    Rotation buys breadth: one task per class per pass. Over the terminal tail
    that interleaves by definition — A, B, A — and the third dispatch is a
    terminal class after a later-declared one, which the guard stops the run
    over. So the shape that exposed it is a plan holding TWO tasks for the
    earlier-declared class and one for the later: with one task each, a rotation
    and a drain are the same sequence and the defect is invisible.

    The guard has been correct since it landed. The dispatcher was
    legal-and-wrong, and the run it killed was a legitimate one.

    Two tests, measuring two different things. The first runs the real
    dispatcher with the real guard and asserts the ORDER. The second turns the
    guard off and asserts the DRAIN — that one class's queue is empty before the
    next class is drawn — because a test that only ever sees the guard raise is
    measuring the guard, and the guard is not the half that changed.
    """

    @staticmethod
    def _agent() -> ExploitAgent:
        agent = ExploitAgent.__new__(ExploitAgent)
        agent._logger = logging.getLogger("test.exploit.drain")
        agent._tests_run = 0
        agent._stopped_early = False
        agent._category_max_findings = 5
        agent._category_time_budget = 90.0
        return agent

    def test_the_drain_helper_yields_at_most_one_class(self) -> None:
        """The narrowing itself: eligibility, not a sort order.

        A helper that returned the declaration-ordered LIST would be obeyed by a
        per-pass loop as a rotation over it, which is what happened.
        """
        declared = sorted(TERMINAL_DISPATCH_CLASSES, key=terminal_dispatch_rank)
        assert terminal_drain_order(declared) == declared[:1]
        assert terminal_drain_order(list(reversed(declared))) == declared[:1]
        assert terminal_drain_order([]) == []
        for method in declared:
            assert terminal_drain_order([method]) == [method]

    @pytest.mark.skipif(
        len(TERMINAL_DISPATCH_CLASSES) < 2,
        reason="the ordering among terminal classes only exists once there are two",
    )
    @pytest.mark.asyncio
    async def test_two_for_the_earlier_class_then_one_for_the_later(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The observed failing shape, with the guard live and expected silent.

        Two write-crossing tasks and one pollution task. The rotation dispatched
        W, P, W and the guard stopped the run on the third — a correct refusal of
        an order the dispatcher should never have proposed.
        """
        declared = sorted(TERMINAL_DISPATCH_CLASSES, key=terminal_dispatch_rank)
        earlier, later = declared[0], declared[1]
        agent = self._agent()
        dispatched: list[str] = []

        async def _execute(task: ExploitTask, cache: dict) -> list:
            dispatched.append(task.test_method)
            return []

        monkeypatch.setattr(agent, "_execute_task", _execute)
        monkeypatch.setattr(agent, "_should_stop_dispatching", lambda: False)
        monkeypatch.setattr(agent, "_trace_dispatch_ordinal", lambda task, ordinal: None)

        plan = ExploitPlan(
            tasks=[
                ExploitTask(test_method=earlier, endpoint_url="http://t/api/a", tier=1),
                ExploitTask(test_method=earlier, endpoint_url="http://t/api/b", tier=1),
                ExploitTask(test_method=later, endpoint_url="http://t/api/c", tier=1),
            ]
        )
        await agent._step_execute_exploits(plan, None)

        assert dispatched == [earlier, earlier, later], dispatched

    @pytest.mark.skipif(
        len(TERMINAL_DISPATCH_CLASSES) < 2,
        reason="the ordering among terminal classes only exists once there are two",
    )
    @pytest.mark.asyncio
    async def test_a_class_queue_is_empty_before_the_next_is_drawn(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The drain asserted DIRECTLY, with the guard neutralised.

        The guard is switched off here on purpose. With it live, a re-introduced
        rotation fails this file by raising, and a test that can only observe the
        exception cannot tell a dispatcher that drains from one that interleaves
        and gets caught. So the assertion is made on the sequence itself: at the
        moment a terminal class is first drawn, every terminal class declared
        before it must already have dispatched every task the plan gave it.
        """
        monkeypatch.setattr(
            exploit_module, "assert_terminal_dispatch_order", lambda method, seen: None
        )
        declared = sorted(TERMINAL_DISPATCH_CLASSES, key=terminal_dispatch_rank)
        earlier, later = declared[0], declared[1]
        agent = self._agent()

        plan = ExploitPlan(
            tasks=[
                ExploitTask(test_method="_test_sqli", endpoint_url="http://t/p?id=1", tier=1),
                ExploitTask(test_method=later, endpoint_url="http://t/api/p1", tier=1),
                ExploitTask(test_method=earlier, endpoint_url="http://t/api/w1", tier=1),
                ExploitTask(test_method=later, endpoint_url="http://t/api/p2", tier=1),
                ExploitTask(test_method=earlier, endpoint_url="http://t/api/w2", tier=1),
                ExploitTask(test_method=earlier, endpoint_url="http://t/api/w3", tier=1),
            ]
        )
        planned: dict[str, int] = {}
        for task in plan.tasks:
            planned[task.test_method] = planned.get(task.test_method, 0) + 1

        dispatched: list[str] = []
        done: dict[str, int] = dict.fromkeys(planned, 0)
        violations: list[str] = []

        async def _execute(task: ExploitTask, cache: dict) -> list:
            method = task.test_method
            if method in TERMINAL_DISPATCH_CLASSES and method not in dispatched:
                rank = terminal_dispatch_rank(method)
                for other in TERMINAL_DISPATCH_CLASSES:
                    if terminal_dispatch_rank(other) >= rank or other not in planned:
                        continue
                    if done[other] != planned[other]:
                        violations.append(
                            f"{method} was drawn with {planned[other] - done[other]} "
                            f"task(s) still queued for {other}"
                        )
            dispatched.append(method)
            done[method] += 1
            return []

        monkeypatch.setattr(agent, "_execute_task", _execute)
        monkeypatch.setattr(agent, "_should_stop_dispatching", lambda: False)
        monkeypatch.setattr(agent, "_trace_dispatch_ordinal", lambda task, ordinal: None)
        await agent._step_execute_exploits(plan, None)

        assert not violations, violations
        # And the whole sequence, so the drain is visible rather than inferred.
        assert dispatched == ["_test_sqli", earlier, earlier, earlier, later, later], dispatched
        assert len(dispatched) == len(plan.tasks), "the drain dropped a planned task"
