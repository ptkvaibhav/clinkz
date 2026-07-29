"""Regression tests for D1 batch-2 coverage + adaptation (G4, G5).

G4 — the four D1 baseline runs truncated ~1500 candidate tasks to 150 silently.
     ``_test_cmdi`` never reached the endpoint carrying a command parameter in
     three of the four runs, and ``_test_weak_session`` logged zero
     methodology-phase events in all four. Both are ordering failures: each
     class's first task went to whatever the crawler surfaced first.

G5 — at DVWA ``medium`` the SQLi ladder ran 9 verifications and emitted 0; at
     ``high``, 15 and 0. Two generic causes: a ``content_diff`` verification
     selected without a control payload (structurally unable to run), and a
     ladder that re-sent the same quoted string-break on a target that escapes
     quotes, never trying the other SQL context.
"""

from __future__ import annotations

import logging

import pytest

from clinkz.agents.exploit import (
    ExploitAgent,
    PageAnalysis,
    _endpoint_class_relevance,
    _has_repeated_path_block,
    _HTTPResponse,
    _serves_own_source,
)
from clinkz.models.finding import ExploitPlan, ExploitTask
from clinkz.models.methodology import (
    FileUploadExecutionType,
    FileUploadRestrictions,
    SQLDialect,
    SQLiMethodologyResult,
)
from clinkz.models.scan import Endpoint


def _agent(max_plan_tasks: int = 150) -> ExploitAgent:
    agent = ExploitAgent.__new__(ExploitAgent)
    agent._logger = logging.getLogger("test.plan.coverage")
    agent._max_plan_tasks = max_plan_tasks
    agent._session_headers = {}
    agent._session_cookies = {}
    agent._unproven_exploit_leads = []
    return agent


def _dvwa_shaped_crawl() -> list[Endpoint]:
    """A crawl with the shape the live runs produced: bulk noise first, the
    endpoints that actually hold vulns last."""
    eps: list[Endpoint] = []
    # Source-viewer family — one per module, all parameterised GETs, which is
    # why they used to sort ahead of everything real.
    for i in range(40):
        eps.append(
            Endpoint(url=f"http://t/app/view_source_all.php?id=mod{i}", method="GET", params=["id"])
        )
    # Doubled-path crawl artifacts (relative-link resolution bug; these 404).
    for i in range(25):
        eps.append(
            Endpoint(url=f"http://t/app/app/x{i}/source/low.php", method="GET", params=["id"])
        )
    # Static assets.
    for i in range(20):
        eps.append(Endpoint(url=f"http://t/static/css/s{i}.css", method="GET", params=[]))
    # Documentation / translations.
    for loc in ("en", "de", "fr", "es"):
        eps.append(Endpoint(url=f"http://t/docs/README.{loc}.md", method="GET", params=[]))
    # The real surfaces.
    eps += [
        Endpoint(url="http://t/app/search/?name=x", method="GET", params=["name"]),
        Endpoint(url="http://t/app/include/?page=home.php", method="GET", params=["page"]),
        Endpoint(url="http://t/app/exec/", method="POST", params=["ip", "Submit", "user_token"]),
        Endpoint(url="http://t/app/upload/", method="POST", params=["file", "Upload"]),
        Endpoint(url="http://t/login.php", method="POST", params=["username", "password"]),
        Endpoint(url="http://t/app/records/?id=1", method="GET", params=["id"]),
    ]
    return eps


# ===========================================================================
# G4 — class-relevance ordering, noise filtering, and loud truncation
# ===========================================================================


class TestG4CrawlNoise:
    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("/app/app/x/source/low.php", True),
            ("/vulnerabilities/vulnerabilities/upload/", True),
            ("/a/b/a/b/c", True),
            ("/app/upload/", False),
            ("/", False),
            ("/one", False),
        ],
    )
    def test_doubled_path_blocks_are_detected_structurally(self, path: str, expected: bool) -> None:
        """Detected by shape, not by naming one target's doubled prefix — the
        literal ``/vulnerabilities/vulnerabilities/`` this replaced was a
        benchmark constant in what is supposed to be general code."""
        assert _has_repeated_path_block(path) is expected

    def test_noise_is_deprioritised_below_real_surfaces(self) -> None:
        agent = _agent()
        ranked = agent._dedupe_and_rank_endpoints(_dvwa_shaped_crawl())
        top = [e.url for e in ranked[:6]]
        assert all("/app/app/" not in u for u in top)
        assert all(not u.endswith(".css") and not u.endswith(".md") for u in top)


class TestG4DirectoryNamesAreNotEvidence:
    """A low-value marker must identify the PAGE, never a directory it sits under.

    A bare ``/source/`` entry cost real coverage the moment class-relevance
    ordering started reading the list: an app that mounts a live handler under a
    ``source`` directory (``/open_redirect/source/low.php?redirect=``) had that
    endpoint graded as crawl noise and sorted to the back of every bucket, so
    ``_test_open_redirect`` never dispatched against it — engagement
    ``441c5728`` lost the finding its baseline emitted.
    """

    LIVE_HANDLER = "http://t/app/open_redirect/source/low.php?redirect=info.php"
    SOURCE_VIEWER = "http://t/app/view_source_all.php?id=mod"

    def test_a_live_handler_under_a_source_directory_ranks_top(self) -> None:
        ep = Endpoint(url=self.LIVE_HANDLER, method="GET", params=["redirect"])
        assert _endpoint_class_relevance("_test_open_redirect", ep) == 0

    def test_the_source_viewer_page_is_still_demoted(self) -> None:
        """Removing the directory entry must not readmit the viewer family — it
        is matched by filename, which is what actually names the page."""
        ep = Endpoint(url=self.SOURCE_VIEWER, method="GET", params=["id"])
        assert _endpoint_class_relevance("_test_cmdi", ep) == 3

    def test_doubled_paths_are_still_demoted(self) -> None:
        ep = Endpoint(url="http://t/app/app/x/source/low.php", method="GET", params=["id"])
        assert _endpoint_class_relevance("_test_cmdi", ep) == 3


class TestG4ClassRelevance:
    def test_command_parameter_outranks_a_source_viewer_for_cmdi(self) -> None:
        cmd_ep = Endpoint(url="http://t/app/exec/", method="POST", params=["ip", "Submit"])
        noise = Endpoint(url="http://t/app/view_source_all.php?id=x", method="GET", params=["id"])
        assert _endpoint_class_relevance("_test_cmdi", cmd_ep) == 0
        assert _endpoint_class_relevance("_test_cmdi", noise) == 3

    def test_relevance_is_per_class_not_global(self) -> None:
        """The same endpoint ranks differently for different classes — that is
        the whole point of ordering per class rather than once, globally."""
        file_ep = Endpoint(url="http://t/app/include/?page=home.php", method="GET", params=["page"])
        assert _endpoint_class_relevance("_test_lfi", file_ep) == 0
        assert _endpoint_class_relevance("_test_cmdi", file_ep) == 2

    def test_each_class_first_task_is_its_most_relevant_endpoint(self) -> None:
        """The live defect, reproduced and fixed: ``_test_cmdi``'s first task is
        the endpoint with a command parameter, not endpoint #1 of the crawl."""
        agent = _agent()
        ranked = agent._dedupe_and_rank_endpoints(_dvwa_shaped_crawl())
        plan = agent._build_deterministic_plan(ranked, [], [])
        first: dict[str, str] = {}
        for task in plan.tasks:
            first.setdefault(task.test_method, task.endpoint_url)
        assert first["_test_cmdi"] == "http://t/app/exec/"
        assert first["_test_lfi"] == "http://t/app/include/?page=home.php"
        assert first["_test_file_upload"] == "http://t/app/upload/"
        assert first["_test_brute_force"] == "http://t/login.php"


class TestG4CsrfOnGetForms:
    """A state-changing form served over GET must still reach ``_test_csrf``.

    The POST gate cost real coverage: DVWA's password-change form is
    ``<form action="#" method="GET">``, so the class reached that endpoint only
    when the LLM plan happened to name it. Engagement ``783fb78b`` — whose plan
    held 4 tasks — lost the CSRF finding its predecessor emitted. Same shape as
    the brute-force and upload gates, which were already queued by endpoint
    shape rather than declared method.
    """

    def _methods(self, url: str, method: str = "GET") -> list[str]:
        agent = _agent()
        return agent._applicable_methods_for_endpoint(Endpoint(url=url, method=method, params=[]))

    def test_get_method_csrf_surface_is_queued(self) -> None:
        assert "_test_csrf" in self._methods("http://t/vulnerabilities/csrf/")

    def test_get_method_account_surface_is_queued(self) -> None:
        assert "_test_csrf" in self._methods("http://t/account/password/change")

    def test_an_ordinary_page_is_not_queued_for_csrf(self) -> None:
        """The gate narrows the queue; phase-1's state-changing hypothesis is
        still the honest filter, so this must not become "every endpoint"."""
        assert "_test_csrf" not in self._methods("http://t/app/search/", "GET")

    def test_post_endpoints_keep_their_existing_queue(self) -> None:
        assert "_test_csrf" in self._methods("http://t/api/items", "POST")


class TestG4TruncationIsLoud:
    def test_dropped_tasks_are_logged_per_class(self, caplog: pytest.LogCaptureFixture) -> None:
        """A plan that silently drops nine tenths of its candidates reads exactly
        like a plan that covered everything."""
        agent = _agent(max_plan_tasks=20)
        ranked = agent._dedupe_and_rank_endpoints(_dvwa_shaped_crawl())
        with caplog.at_level(logging.WARNING, logger="test.plan.coverage"):
            agent._build_deterministic_plan(ranked, [], [])
        messages = [r.getMessage() for r in caplog.records]
        assert any("TRUNCATED" in m for m in messages)
        assert any("_test_cmdi=" in m for m in messages)

    def test_no_truncation_message_when_everything_fits(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        agent = _agent(max_plan_tasks=5000)
        ranked = agent._dedupe_and_rank_endpoints(_dvwa_shaped_crawl())
        with caplog.at_level(logging.WARNING, logger="test.plan.coverage"):
            agent._build_deterministic_plan(ranked, [], [])
        assert not any("TRUNCATED" in r.getMessage() for r in caplog.records)


class TestG4PerClassFloor:
    def test_a_cap_filling_llm_plan_cannot_starve_a_class(self) -> None:
        """``_test_weak_session`` logged zero phase events in all four baseline
        runs: the LLM plan filled the cap, so the coverage union added nothing
        and classes the planner never mentioned were never queued."""
        agent = _agent(max_plan_tasks=30)
        ranked = agent._dedupe_and_rank_endpoints(_dvwa_shaped_crawl())
        llm_plan = ExploitPlan(
            tasks=[
                ExploitTask(
                    test_method="_test_sqli",
                    endpoint_url=f"http://t/app/view_source_all.php?id=mod{i}",
                    endpoint_params=["id"],
                    tier=1,
                    priority=i,
                )
                for i in range(30)
            ],
            tier1_count=30,
        )
        merged = agent._merge_coverage(llm_plan, ranked, [], [])
        classes = {t.test_method for t in merged.tasks}
        assert "_test_weak_session" in classes
        assert "_test_cmdi" in classes
        # The floor takes the class's MOST relevant endpoint, not an arbitrary one.
        cmdi = next(t for t in merged.tasks if t.test_method == "_test_cmdi")
        assert cmdi.endpoint_url == "http://t/app/exec/"

    def test_the_floor_never_duplicates_a_class_the_plan_covers(self) -> None:
        agent = _agent(max_plan_tasks=200)
        ranked = agent._dedupe_and_rank_endpoints(_dvwa_shaped_crawl())
        llm_plan = ExploitPlan(
            tasks=[
                ExploitTask(
                    test_method="_test_cmdi",
                    endpoint_url="http://t/app/exec/",
                    endpoint_params=["ip", "Submit", "user_token"],
                    tier=1,
                    priority=0,
                )
            ],
            tier1_count=1,
        )
        merged = agent._merge_coverage(llm_plan, ranked, [], [])
        keys = [
            agent._coverage_key(t.test_method, t.endpoint_url, t.endpoint_params)
            for t in merged.tasks
        ]
        assert len(keys) == len(set(keys))


# ===========================================================================
# G5 — the ladders adapt
# ===========================================================================


class TestG5IndicatorRouting:
    def test_content_diff_without_a_control_reroutes_by_payload_shape(self) -> None:
        """A ``content_diff`` verification needs both shapes. Without a control
        it returned "missing control_payload" having sent nothing — three wasted
        rungs across the medium/high runs, always on a UNION payload."""
        agent = _agent()
        assert (
            agent._normalise_indicator_type("content_diff", "1' UNION SELECT NULL,NULL-- -", None)
            == "union_data"
        )
        assert (
            agent._normalise_indicator_type("boolean_blind", "1' AND SLEEP(5)-- -", None)
            == "time_delta"
        )

    def test_content_diff_with_a_control_is_untouched(self) -> None:
        agent = _agent()
        assert (
            agent._normalise_indicator_type("content_diff", "1 AND 1=1", "1 AND 1=2")
            == "content_diff"
        )


def _baselines(body: str = "A" * 500, value: str = "1") -> list[dict[str, object]]:
    """Phase-1 baseline records in the shape ``_sqli_phase1_injection_point`` returns."""
    return [
        {"variant": v, "value": value, "status": 200, "length": len(body), "body": body}
        for v in ("original", "single_quote", "double_quote")
    ]


class TestG5SQLiContextAdaptation:
    @pytest.mark.asyncio
    async def test_numeric_context_is_tried_when_the_quoted_break_fails(self) -> None:
        """The generic adaptation: the quoted break produced no differential on
        every ranked type, so the injection point is not a string literal (or
        the quote is neutralised). Drop the quote and inject directly."""
        agent = _agent()
        sent: list[str] = []

        async def fake_probe(page: PageAnalysis, param: str, value: str) -> _HTTPResponse:
            sent.append(value)
            # Only the unquoted boolean shapes produce a differential.
            if value == "1 AND 1=2":
                return _HTTPResponse(status=200, body="A" * 200)
            return _HTTPResponse(status=200, body="A" * 500)

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        agent._original_param_value = lambda page, param: "1"  # type: ignore[method-assign]
        agent._trace_methodology_phase = lambda **kw: None  # type: ignore[method-assign]

        result = SQLiMethodologyResult(candidate_param="id", dialect=SQLDialect.MYSQL)
        page = PageAnalysis(url="http://t/app/records/", body="", status=200, input_params=["id"])
        await agent._sqli_adapt_context(page, "id", result, _baselines())

        assert result.verified is True
        assert result.synthesized_payload == "1 AND 1=1"
        assert "context adaptation" in (result.indicator_observed or "")
        assert "1 AND 1=1" in sent  # the rung dropped the quote
        assert not any("'" in value for value in sent)

    @pytest.mark.asyncio
    async def test_adaptation_stays_silent_when_nothing_differs(self) -> None:
        """No differential in any context ⇒ nothing verified, nothing emitted.
        The ladder gains reach, never a new way to confirm."""
        agent = _agent()
        agent._send_probe = lambda page, param, value: _identical()  # type: ignore[method-assign]
        agent._original_param_value = lambda page, param: "1"  # type: ignore[method-assign]
        agent._trace_methodology_phase = lambda **kw: None  # type: ignore[method-assign]

        result = SQLiMethodologyResult(candidate_param="id", dialect=SQLDialect.MYSQL)
        page = PageAnalysis(url="http://t/app/records/", body="", status=200, input_params=["id"])
        await agent._sqli_adapt_context(page, "id", result, _baselines())
        assert result.verified is False


async def _identical() -> _HTTPResponse:
    return _HTTPResponse(status=200, body="A" * 500)


class TestG5LadderIsGatedBoundedAndDiagnosable:
    """The batch-3 diagnosis, encoded.

    Across the six D1 runs the ladder fired 110 rungs and confirmed nothing, and
    106 of those rungs reported the true-shape and false-shape bodies
    byte-identical: it was firing on parameters that reach no query at all. Every
    SQL confirmation in every run came from phase-4 synthesis or the
    session-indirection carrier.
    """

    def test_no_query_context_means_the_ladder_never_fires(self) -> None:
        """The live shapes it was wasted on: a reflected text field whose only
        response change was the echoed quote (4767 → 4768 bytes) and a file-include
        path whose quote variant failed the include (5236 → 4735). Neither has a
        dialect, a break prefix, or a DB error, so no rung can differentiate."""
        agent = _agent()
        result = SQLiMethodologyResult(candidate_param="name")
        fire, reason = agent._sqli_ladder_precondition(result, _baselines("B" * 4768))
        assert fire is False
        assert "no query context demonstrated" in reason

    def test_each_query_context_signal_lets_it_fire(self) -> None:
        agent = _agent()
        by_dialect = SQLiMethodologyResult(candidate_param="id", dialect=SQLDialect.MYSQL)
        assert agent._sqli_ladder_precondition(by_dialect, _baselines())[0] is True

        by_break = SQLiMethodologyResult(candidate_param="id")
        by_break.primitives.break_prefix = ""
        fire, reason = agent._sqli_ladder_precondition(by_break, _baselines())
        assert fire is True and "break prefix" in reason

        with_error = _baselines()
        with_error[1]["body"] = "You have an error in your SQL syntax near ''' at line 1"
        fire, reason = agent._sqli_ladder_precondition(
            SQLiMethodologyResult(candidate_param="id"), with_error
        )
        assert fire is True and "DB error signature" in reason

    @pytest.mark.asyncio
    async def test_ungated_parameter_costs_zero_requests(self) -> None:
        agent = _agent()
        sent: list[str] = []

        async def fake_probe(page: PageAnalysis, param: str, value: str) -> _HTTPResponse:
            sent.append(value)
            return _HTTPResponse(status=200, body="A" * 500)

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        agent._original_param_value = lambda page, param: "1"  # type: ignore[method-assign]
        agent._trace_methodology_phase = lambda **kw: None  # type: ignore[method-assign]

        result = SQLiMethodologyResult(candidate_param="page")
        page = PageAnalysis(url="http://t/app/fi/", body="", status=200, input_params=["page"])
        await agent._sqli_adapt_context(page, "page", result, _baselines())
        assert sent == []
        assert result.verified is False

    @pytest.mark.asyncio
    async def test_invariant_response_aborts_the_ladder_early(self) -> None:
        """Once two consecutive rungs prove the response does not vary with the
        parameter, the remaining rungs cannot produce a differential. The live runs
        re-learned that fact five times per parameter."""
        agent = _agent()
        rungs: list[str] = []

        async def fake_probe(page: PageAnalysis, param: str, value: str) -> _HTTPResponse:
            rungs.append(value)
            return _HTTPResponse(status=200, body="A" * 500)

        traced: list[dict[str, object]] = []
        agent._send_probe = fake_probe  # type: ignore[method-assign]
        agent._original_param_value = lambda page, param: "1"  # type: ignore[method-assign]
        agent._trace_methodology_phase = lambda **kw: traced.append(kw)  # type: ignore[method-assign]

        result = SQLiMethodologyResult(candidate_param="id", dialect=SQLDialect.MYSQL)
        page = PageAnalysis(url="http://t/app/records/", body="", status=200, input_params=["id"])
        await agent._sqli_adapt_context(page, "id", result, _baselines())

        summary = next(t for t in traced if t["phase_name"] == "context_adaptation_summary")
        assert summary["extra"]["rungs_fired"] == 2  # not all five
        assert "invariant to the injected predicate" in summary["extra"]["aborted"]
        assert result.verified is False

    @pytest.mark.asyncio
    async def test_every_rung_records_a_deterministic_failure_cause(self) -> None:
        """G5's explicit ask: for each rung, what was attempted, what came back,
        and WHY it failed — in a closed vocabulary, so a zero-confirmation run is
        diagnosable from the trace instead of by re-deriving it from byte counts."""
        agent = _agent()

        async def fake_probe(page: PageAnalysis, param: str, value: str) -> _HTTPResponse:
            # Every shape returns the same page: the parameter has no influence.
            return _HTTPResponse(status=200, body="A" * 500)

        traced: list[dict[str, object]] = []
        agent._send_probe = fake_probe  # type: ignore[method-assign]
        agent._original_param_value = lambda page, param: "1"  # type: ignore[method-assign]
        agent._trace_methodology_phase = lambda **kw: traced.append(kw)  # type: ignore[method-assign]

        result = SQLiMethodologyResult(candidate_param="id", dialect=SQLDialect.MYSQL)
        page = PageAnalysis(url="http://t/app/records/", body="", status=200, input_params=["id"])
        await agent._sqli_adapt_context(page, "id", result, _baselines())

        per_rung = [t for t in traced if t["phase_name"] == "context_adaptation"]
        assert per_rung
        for event in per_rung:
            extra = event["extra"]
            assert extra["cause"] == "response_invariant_to_payload"
            assert extra["payload"] and extra["control_payload"]
            assert extra["indicator_observed"]


class TestG14SelfEvidencingBooleanDifferential:
    """A thin-but-real differential must carry its own control.

    Six bytes is deterministic proof when it reproduces exactly against a
    contemporaneous baseline — and a reviewer that cannot see the repeats calls it
    variance (``fe234e99``). So the oracle repeats the whole baseline/true/false
    triple and renders all of it into the evidence.
    """

    @staticmethod
    def _agent_with(bodies: dict[str, list[str]]) -> tuple[ExploitAgent, list[str]]:
        """An agent whose probe replays a per-value queue of response bodies."""
        agent = _agent()
        sent: list[str] = []
        counters: dict[str, int] = {}

        async def fake_probe(page: PageAnalysis, param: str, value: str) -> _HTTPResponse:
            sent.append(value)
            queue = bodies[value]
            index = counters.get(value, 0)
            counters[value] = index + 1
            return _HTTPResponse(status=200, body=queue[min(index, len(queue) - 1)])

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        agent._original_param_value = lambda page, param: "1"  # type: ignore[method-assign]
        agent._trace_methodology_phase = lambda **kw: None  # type: ignore[method-assign]
        return agent, sent

    @pytest.mark.asyncio
    async def test_a_stable_six_byte_delta_confirms_and_evidences_itself(self) -> None:
        """The exact live shape: DVWA's blind page swaps "User ID exists in the
        database." for "User ID is MISSING from the database." — 4842 vs 4848
        bytes, reproducing every time."""
        agent, sent = self._agent_with(
            {
                "1": ["A" * 4842] * 3,
                "1 AND 1=1": ["A" * 4842] * 3,
                "1 AND 1=2": ["B" * 4848] * 3,
            }
        )
        page = PageAnalysis(url="http://t/app/blind/", body="", status=200, input_params=["id"])
        verified, observed, cause = await agent._sqli_verify_boolean_differential(
            page, "id", "1 AND 1=1", "1 AND 1=2", {"value": "1", "length": 4842}
        )
        assert verified is True
        assert cause == "confirmed"
        # The observation IS the control: baseline, true and false per repeat.
        assert "baseline=[4842, 4842, 4842]B" in observed
        assert "true=[4842, 4842, 4842]B" in observed
        assert "false=[4848, 4848, 4848]B" in observed
        assert "false-minus-true=+6B identical in every repeat" in observed
        # Three repeats of the triple, baseline re-measured each time.
        assert sent.count("1") == 3
        assert sent.count("1 AND 1=1") == 3
        assert sent.count("1 AND 1=2") == 3

    @pytest.mark.asyncio
    async def test_a_delta_that_appears_once_no_longer_confirms(self) -> None:
        """This is the direction the gate moves: STRICTER. A single lucky pair used
        to be enough; an unreproducible delta is exactly what a thin differential
        must never be."""
        agent, _ = self._agent_with(
            {
                "1": ["A" * 4842] * 3,
                "1 AND 1=1": ["A" * 4842] * 3,
                # Diverges on the first repeat only.
                "1 AND 1=2": ["B" * 4848, "A" * 4842, "A" * 4842],
            }
        )
        page = PageAnalysis(url="http://t/app/blind/", body="", status=200, input_params=["id"])
        verified, observed, cause = await agent._sqli_verify_boolean_differential(
            page, "id", "1 AND 1=1", "1 AND 1=2", {"value": "1", "length": 4842}
        )
        assert verified is False
        assert cause == "differential_not_reproducible"
        assert "no stable boolean differential" in observed

    @pytest.mark.asyncio
    async def test_an_invariant_response_names_that_cause(self) -> None:
        agent, _ = self._agent_with(
            {
                "1": ["A" * 500] * 3,
                "1 AND 1=1": ["A" * 500] * 3,
                "1 AND 1=2": ["A" * 500] * 3,
            }
        )
        page = PageAnalysis(url="http://t/app/fi/", body="", status=200, input_params=["page"])
        verified, _observed, cause = await agent._sqli_verify_boolean_differential(
            page, "page", "1 AND 1=1", "1 AND 1=2", {"value": "1", "length": 500}
        )
        assert verified is False
        assert cause == "response_invariant_to_payload"

    @pytest.mark.asyncio
    async def test_a_broken_page_is_not_a_differential(self) -> None:
        """The TRUE shape must reproduce the benign result set. A true response
        that walks away from its own baseline broke the query instead of
        satisfying it."""
        agent, _ = self._agent_with(
            {
                "1": ["A" * 4842] * 3,
                "1 AND 1=1": ["A" * 20] * 3,
                "1 AND 1=2": ["B" * 30] * 3,
            }
        )
        page = PageAnalysis(url="http://t/app/blind/", body="", status=200, input_params=["id"])
        verified, _observed, cause = await agent._sqli_verify_boolean_differential(
            page, "id", "1 AND 1=1", "1 AND 1=2", {"value": "1", "length": 4842}
        )
        assert verified is False
        assert cause == "true_shape_diverged_from_baseline"


class TestG15SourceViewPagesAreNotExploitationTargets:
    """Source listings and live handlers are told apart by the RESPONSE.

    A path fragment is not evidence about a route — grading a bare ``/source/``
    segment as noise cost a real Open Redirect finding (``ee286e2``). DVWA is the
    worked example in both directions: ``open_redirect/source/<level>.php`` files
    ARE the live handlers its module index links to (they run and issue the
    redirect), while ``view_source.php`` renders them escaped in a code block.
    """

    def test_raw_php_source_served_instead_of_executed_is_refused(self) -> None:
        raw = "<?php\n\nheader('location: ' . $_GET['redirect']);\n"
        assert _serves_own_source(raw) is not None
        assert _serves_own_source("\n  <?= $x ?>") is not None
        assert _serves_own_source("#!/usr/bin/env python\nimport os\n") is not None

    def test_a_highlighted_source_viewer_is_refused(self) -> None:
        body = "<h1>Source</h1><pre><code>&lt;?php echo 1; ?&gt;</code></pre>"
        assert _serves_own_source(body) is not None

    def test_a_live_handler_response_is_not_refused(self) -> None:
        """DVWA's ``open_redirect/source/low.php`` executes: on a request with no
        target it emits its 500 page, and with one it 302s. Neither response
        carries an un-executed prologue, so the guard leaves it alone."""
        assert _serves_own_source("<p>Missing redirect target.</p>") is None
        assert _serves_own_source("") is None

    def test_stored_user_content_mentioning_php_is_not_a_source_listing(self) -> None:
        """The guard is anchored at the start of the body, so a guestbook holding a
        previous engagement's stored probe is not mistaken for a listing — that
        would silently drop the stored-XSS surface."""
        stored = "<div>Message: <?php echo 1; ?></div>"
        body = f"<html><body><div>Name: tester</div>{stored}</body></html>"
        assert _serves_own_source(body) is None

    def test_a_live_handler_under_a_source_directory_is_never_graded_as_noise(self) -> None:
        """The other direction G15 asks for, held against every class that could
        plausibly claim the endpoint."""
        ep = Endpoint(
            url="http://t/app/open_redirect/source/low.php?redirect=info.php?id=2",
            method="GET",
            params=["redirect"],
        )
        assert _endpoint_class_relevance("_test_open_redirect", ep) == 0
        assert _endpoint_class_relevance("_test_sqli", ep) < 3
        assert _endpoint_class_relevance("_test_cmdi", ep) < 3


class TestG5UploadImageCarrier:
    def test_inclusion_chain_uses_the_image_carrier_when_no_script_extension_works(
        self,
    ) -> None:
        """At the hardened levels every script extension was rejected, so
        ``working_extensions`` was empty and synthesis fell back to a ``.txt``
        that proves nothing. A store that still accepts ``x.jpg`` holding a
        script body IS the upload half of an inclusion chain."""
        agent = _agent()
        restrictions = FileUploadRestrictions(working_extensions=[], image_carrier_extension=".jpg")
        synth = agent._fallback_file_upload_synthesis(
            FileUploadExecutionType.INCLUSION_CHAIN, restrictions
        )
        assert synth is not None
        assert synth["filename"].endswith(".jpg")
        assert synth["magic_prefix"] == "GIF89a"
        assert synth["content"].startswith("GIF89a")

    def test_a_working_script_extension_still_wins(self) -> None:
        agent = _agent()
        restrictions = FileUploadRestrictions(
            working_extensions=[".phtml"], image_carrier_extension=".jpg"
        )
        synth = agent._fallback_file_upload_synthesis(
            FileUploadExecutionType.INCLUSION_CHAIN, restrictions
        )
        assert synth is not None
        assert synth["filename"].endswith(".phtml")
        assert synth["magic_prefix"] == ""


class TestDirectExecutionWalksTheConfirmedExtensionSet:
    """Accepted-by-the-store is not executed-by-the-server.

    Phase 2's `working_extensions` records what the upload *accepted*; the server's
    handler mapping decides what *runs*. On the DVWA image Apache ships
    `<FilesMatch \\.php$>`, so `.phtml` uploads fine and is then served as inert
    text. Phase-4 synthesis picks one extension, and at `low` the live model picked
    `.phtml` on both upload tasks of engagement `ad62e582` — direct execution failed
    to verify and the CRITICAL finding its three predecessor runs emitted went
    missing, on a payload choice rather than on the target's posture. A
    deterministic skill is a contract: if the vuln is present the method MUST find
    it, not find it when the model guesses well.
    """

    @staticmethod
    def _restrictions() -> FileUploadRestrictions:
        return FileUploadRestrictions(working_extensions=[".php", ".phtml", ".svg"])

    def test_the_llm_pick_is_tried_first_then_the_rest_of_the_set(self) -> None:
        agent = _agent()
        llm_pick = {
            "filename": "shell.phtml",
            "content": "<?php echo 'x'; ?>",
            "content_type": "image/jpeg",
            "magic_prefix": "",
            "rationale": "the model's choice",
            "canary": "clinkzupload12345",
        }
        candidates = agent._file_upload_execution_candidates(llm_pick, self._restrictions())
        names = [c["filename"] for c in candidates]
        assert names[0] == "shell.phtml"  # synthesis still goes first
        assert any(n.endswith(".php") for n in names[1:])  # the executable one follows
        # The canary is carried across attempts, so the oracle looks for one token.
        assert {c["canary"] for c in candidates} == {"clinkzupload12345"}

    def test_the_extension_already_tried_is_not_repeated(self) -> None:
        agent = _agent()
        llm_pick = {
            "filename": "clinkz_pop.php",
            "content": "<?php echo 'x'; ?>",
            "content_type": "application/x-php",
            "magic_prefix": "",
            "rationale": "",
            "canary": "c1",
        }
        candidates = agent._file_upload_execution_candidates(llm_pick, self._restrictions())
        suffixes = [c["filename"].rsplit(".", 1)[-1] for c in candidates]
        assert suffixes.count("php") == 1

    def test_only_confirmed_extensions_are_retried_and_the_walk_is_bounded(self) -> None:
        """An extension the store rejected is not worth an upload, and the walk
        never grows past the attempt cap however long the confirmed set is."""
        agent = _agent()
        llm_pick = {
            "filename": "shell.svg",
            "content": "x",
            "content_type": "image/svg+xml",
            "magic_prefix": "",
            "rationale": "",
            "canary": "c1",
        }
        narrow = FileUploadRestrictions(working_extensions=[".php"])
        assert [c["filename"] for c in agent._file_upload_execution_candidates(llm_pick, narrow)][
            1:
        ] == ["clinkz_pop.php"]
        wide = FileUploadRestrictions(
            working_extensions=[".php", ".phtml", ".phar", ".asp", ".aspx", ".jsp"]
        )
        assert len(agent._file_upload_execution_candidates(llm_pick, wide)) == 3

    def test_no_confirmed_script_extension_means_no_retry(self) -> None:
        """Nothing new can confirm: with no confirmed script extension the walk is
        just the synthesis pick, decided by the unchanged phase-5 oracle."""
        agent = _agent()
        llm_pick = {
            "filename": "shell.jpg",
            "content": "x",
            "content_type": "image/jpeg",
            "magic_prefix": "GIF89a",
            "rationale": "",
            "canary": "c1",
        }
        empty = FileUploadRestrictions(working_extensions=[], image_carrier_extension=".jpg")
        assert agent._file_upload_execution_candidates(llm_pick, empty) == [llm_pick]


def test_restrictions_default_to_no_carrier() -> None:
    """The new field is additive: an existing caller sees the old behaviour."""
    assert FileUploadRestrictions().image_carrier_extension == ""
