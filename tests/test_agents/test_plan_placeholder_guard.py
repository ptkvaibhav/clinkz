"""The exploit planner must not turn a template echo into a dispatched task.

Forensics from the four P7 DVWA engagements, taken from their ``trace.jsonl``:

1. The first planning call returned ``""`` (see
   ``tests/test_llm/test_empty_response.py`` for the cause).
2. ``_parse_plan_response("")`` returned ``None``, so the planner re-prompted.
3. The repair prompt dropped the endpoint inventory, the technology list and
   the method vocabulary, and demonstrated the schema with a literal
   ``{"test_method": "...", "endpoint_url": "..."}``. Asked to repair nothing,
   the model echoed the template.
4. Nothing validated ``test_method``, so the echo became one task.
5. ``_merge_coverage`` unioned the deterministic floor on top, which is why the
   runs still produced findings and the defect went unnoticed.
6. At dispatch, ``_technique_permitted("...")`` returns True (an unmapped class
   is permitted by design) and the page was fetched *before* the method was
   resolved — so engagement 946e7036 sent, with the live session cookie:

       GET http://172.20.0.4/...   ->  404

Two independent guards were missing. Either alone would have stopped it.
"""

from __future__ import annotations

from typing import Any

import pytest

from clinkz.agents.exploit import DISPATCHABLE_TEST_METHODS, ExploitAgent
from clinkz.models.scan import Endpoint

#: The repair responses the four engagements actually received, verbatim from
#: each run's ``trace.jsonl``. Two models echoed the template; two filled it
#: with a guess. None of them names a method this engine can dispatch.
RECORDED_REPAIR_RESPONSES: dict[str, str] = {
    "1b23a1ef": '{"tasks": [{"test_method": "...", "endpoint_url": "...", '
    '"tier": 1, "priority": 0}]}',
    "946e7036": '{"tasks": [{"test_method": "...", "endpoint_url": "...", '
    '"tier": 1, "priority": 0}]}',
    "35511096": '{"tasks": [{"test_method": "GET", "endpoint_url": "/", '
    '"tier": 1, "priority": 0}]}',
    "f4b0c5c8": '{"tasks": [{"test_method": "GET", "endpoint_url": "/", '
    '"tier": 1, "priority": 0}]}',
}


def _agent() -> ExploitAgent:
    """An agent with just enough state to parse a plan — no __init__, no IO."""
    import logging

    agent = ExploitAgent.__new__(ExploitAgent)
    agent._logger = logging.getLogger("test.plan-guard")
    return agent


def _endpoints() -> list[Endpoint]:
    return [
        Endpoint(url="http://target/vulnerabilities/sqli/", method="GET", params=["id"]),
        Endpoint(url="http://target/vulnerabilities/xss_r/", method="GET", params=["name"]),
    ]


class TestPlaceholderTasksAreRejected:
    @pytest.mark.parametrize("engagement", sorted(RECORDED_REPAIR_RESPONSES))
    def test_recorded_repair_responses_yield_no_tasks(self, engagement: str) -> None:
        """The exact bytes each engagement received must now produce zero tasks.

        ``None`` (rather than a one-task plan) is what routes the caller to the
        deterministic plan — the correct outcome when the model said nothing
        usable.
        """
        plan = _agent()._parse_plan_response(
            RECORDED_REPAIR_RESPONSES[engagement], _endpoints(), [], []
        )
        assert plan is None

    def test_a_real_method_in_the_same_shape_still_parses(self) -> None:
        """Control: the guard rejects the placeholder, not the format."""
        response = (
            '{"tasks": [{"test_method": "_test_sqli", '
            '"endpoint_url": "http://target/vulnerabilities/sqli/", '
            '"tier": 1, "priority": 0}]}'
        )
        plan = _agent()._parse_plan_response(response, _endpoints(), [], [])
        assert plan is not None
        assert [t.test_method for t in plan.tasks] == ["_test_sqli"]

    def test_valid_tasks_survive_alongside_a_rejected_one(self) -> None:
        """A partly-hallucinated plan keeps its real entries."""
        response = (
            '{"tasks": ['
            '{"test_method": "_test_sqli", "endpoint_url": "http://target/vulnerabilities/sqli/",'
            ' "tier": 1, "priority": 0},'
            '{"test_method": "_test_nonexistent", "endpoint_url": "http://target/x",'
            ' "tier": 1, "priority": 1},'
            '{"test_method": "_test_xss_reflected",'
            ' "endpoint_url": "http://target/vulnerabilities/xss_r/", "tier": 1, "priority": 2}'
            "]}"
        )
        plan = _agent()._parse_plan_response(response, _endpoints(), [], [])
        assert plan is not None
        assert [t.test_method for t in plan.tasks] == ["_test_sqli", "_test_xss_reflected"]

    def test_the_drop_is_logged_not_silent(self, caplog: pytest.LogCaptureFixture) -> None:
        """A planner naming unknown methods is a defect, not quieter planning."""
        with caplog.at_level("WARNING"):
            _agent()._parse_plan_response(
                RECORDED_REPAIR_RESPONSES["1b23a1ef"], _endpoints(), [], []
            )
        assert "non-dispatchable test method" in caplog.text


class TestDispatchTableIsInSync:
    def test_every_dispatchable_name_is_actually_dispatchable(self) -> None:
        """The guard is only as good as the vocabulary it validates against.

        A name in ``DISPATCHABLE_TEST_METHODS`` that ``_execute_task`` cannot
        resolve to a handler would be admitted by the parser and then dropped at
        dispatch — the exact hole this guard exists to close, one level in.

        This used to grep ``_execute_task``'s SOURCE for ``"name": self.name``,
        because the dispatcher rebuilt its own dict of bound methods and the
        declared vocabulary and the dispatch table were two lists that had to be
        kept in step by hand. They are one list now: the dispatcher resolves
        ``getattr(self, task.test_method)`` gated on this very frozenset. So the
        check is on the actual binding rather than on a string appearing in
        source — a test that reads source can pass while the binding is broken,
        and can fail while it is fine.
        """
        for name in DISPATCHABLE_TEST_METHODS:
            handler = getattr(ExploitAgent, name, None)
            assert callable(handler), f"{name} is dispatchable but resolves to no handler"

    def test_every_dispatchable_name_is_a_real_method(self) -> None:
        for name in DISPATCHABLE_TEST_METHODS:
            assert callable(getattr(ExploitAgent, name, None)), f"{name} is not defined"

    def test_the_placeholder_the_model_echoed_is_not_in_the_vocabulary(self) -> None:
        assert "..." not in DISPATCHABLE_TEST_METHODS
        assert "GET" not in DISPATCHABLE_TEST_METHODS


class TestRepairPromptDoesNotHandOverATemplate:
    def test_no_fill_in_the_blank_placeholder_is_offered(self) -> None:
        """The template was the thing the model copied — it must not be there."""
        prompt = ExploitAgent._build_plan_repair_prompt("some malformed output")
        assert '"test_method": "..."' not in prompt
        assert '"endpoint_url": "..."' not in prompt

    def test_the_schema_is_still_stated(self) -> None:
        prompt = ExploitAgent._build_plan_repair_prompt("some malformed output")
        for key in ("tasks", "test_method", "endpoint_url", "tier", "priority"):
            assert key in prompt

    def test_the_bad_response_is_quoted_back(self) -> None:
        prompt = ExploitAgent._build_plan_repair_prompt("<<<the bad output>>>")
        assert "<<<the bad output>>>" in prompt


class TestPlanningPrefixIsByteStable:
    """Part B's requirement, checked where it can actually regress."""

    def _prefix(self, agent: ExploitAgent, **overrides: Any) -> str:
        kwargs: dict[str, Any] = {
            "ranked_endpoints": _endpoints(),
            "technologies": ["php", "apache"],
            "tier2_entries": [{"technique_name": "b"}, {"technique_name": "a"}],
            "runbook": [],
            "prompt_cap": 120,
        }
        kwargs.update(overrides)
        return agent._build_planning_prefix(**kwargs)

    def test_identical_inputs_render_identical_bytes(self) -> None:
        agent = _agent()
        assert self._prefix(agent) == self._prefix(agent)

    def test_technology_order_does_not_change_the_bytes(self) -> None:
        """A set-derived list arrives in a different order each run.

        Unsorted iteration is one of the documented silent cache invalidators,
        and it is the kind that only shows up as a hit rate that never rises.
        """
        agent = _agent()
        a = self._prefix(agent, technologies=["php", "apache", "debian"])
        b = self._prefix(agent, technologies=["debian", "php", "apache"])
        assert a == b

    def test_the_prefix_carries_what_the_planner_was_missing(self) -> None:
        """Asserted on the WHOLE prompt, because that is what the model reads.

        The context is split across two spans now — engine-invariant and
        engagement-scoped — so the cache breakpoint can sit between them. That
        is an accounting boundary and must not be a content one: everything the
        planner needs still has to arrive, and asserting it per span would let
        a section go missing from the prompt while both halves still passed.
        """
        agent = _agent()
        whole = f"{ExploitAgent._planning_invariant_prefix()}\n\n{self._prefix(agent)}"
        # Every method name, each with its precondition — not a bare name list.
        assert "`_test_sqli` — applies when endpoint has params" in whole
        assert "## Methodology catalogue" in whole
        assert "## Planning guidance" in whole
        assert "## Worked examples" in whole
        assert "## Endpoint inventory" in whole
        assert "## Prior-engagement capability priors" in whole

    def test_the_two_spans_do_not_overlap(self) -> None:
        """The engine half must not carry an observation, or it is not invariant."""
        agent = _agent()
        invariant = ExploitAgent._planning_invariant_prefix()
        scoped = self._prefix(agent)
        assert "## Methodology catalogue" in invariant
        assert "## Methodology catalogue" not in scoped
        assert "## Endpoint inventory" in scoped
        assert "## Endpoint inventory" not in invariant

    def test_worked_examples_use_endpoints_that_are_not_in_the_inventory(self) -> None:
        """An example drawn from the real inventory would be an answer, not a shape."""
        from clinkz.agents.exploit import _PLANNING_EXAMPLES

        for endpoint in _endpoints():
            assert endpoint.url not in _PLANNING_EXAMPLES

    def test_the_cached_span_clears_the_cache_floor_for_the_configured_model(self) -> None:
        """Measured on the span that takes the breakpoint, not on the big one.

        This used to measure the engagement-scoped prefix — ~12,500 tokens,
        comfortably over any floor, and utterly beside the point, because that
        span is presented once per run and was never read back. The span that
        now carries the breakpoint is an order of magnitude smaller, which puts
        it near sonnet-5's 1,024-token floor, so whether a breakpoint attaches
        at all is a real question with a measurable answer. If it stops
        clearing the floor, caching silently becomes a no-op and this is the
        only thing that would say so.
        """
        from clinkz.config import settings
        from clinkz.llm.anthropic_client import cache_min_prefix_tokens

        prefix = ExploitAgent._planning_invariant_prefix()
        approx_tokens = len(prefix) // 4  # the client's own conservative estimator
        floor = cache_min_prefix_tokens(settings.anthropic_model)
        assert approx_tokens >= floor, (
            f"the invariant prefix is ~{approx_tokens} tokens, under the {floor}-token "
            f"floor for {settings.anthropic_model}; no breakpoint would attach and "
            f"caching would be a silent no-op"
        )

    def test_a_wasted_write_on_the_cached_span_is_bounded_noise(self) -> None:
        """The worst case has to be affordable, because it will happen.

        A write nothing reads costs the 0.25x premium on the cached span. On
        the old ~12,500-token span that was ~3,100 wasted tokens every run,
        which is what the 154 recorded engagements actually paid. Keep the
        cached span small enough that being wrong is cheap.
        """
        prefix = ExploitAgent._planning_invariant_prefix()
        wasted_tokens = (len(prefix) // 4) * 0.25
        assert wasted_tokens < 500, (
            f"a wasted write would cost ~{wasted_tokens:.0f} tokens; the cached span "
            f"has grown to the point where a miss is no longer noise"
        )
