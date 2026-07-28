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
)
from clinkz.models.finding import ExploitPlan, ExploitTask
from clinkz.models.methodology import FileUploadExecutionType, FileUploadRestrictions
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
            if value == "1 AND 1=1":
                return _HTTPResponse(status=200, body="A" * 500)
            if value == "1 AND 1=2":
                return _HTTPResponse(status=200, body="A" * 200)
            return _HTTPResponse(status=200, body="A" * 500)

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        agent._original_param_value = lambda page, param: "1"  # type: ignore[method-assign]
        agent._trace_methodology_phase = lambda **kw: None  # type: ignore[method-assign]

        from clinkz.models.methodology import SQLiMethodologyResult

        result = SQLiMethodologyResult(candidate_param="id")
        page = PageAnalysis(url="http://t/app/records/", body="", status=200, input_params=["id"])
        await agent._sqli_adapt_context(page, "id", result, {"length": 500, "body": "A" * 500})

        assert result.verified is True
        assert result.synthesized_payload == "1 AND 1=1"
        assert "context adaptation" in (result.indicator_observed or "")
        assert "'" not in sent[0]  # the first rung dropped the quote

    @pytest.mark.asyncio
    async def test_adaptation_stays_silent_when_nothing_differs(self) -> None:
        """No differential in any context ⇒ nothing verified, nothing emitted.
        The ladder gains reach, never a new way to confirm."""
        agent = _agent()
        agent._send_probe = lambda page, param, value: _identical()  # type: ignore[method-assign]
        agent._original_param_value = lambda page, param: "1"  # type: ignore[method-assign]
        agent._trace_methodology_phase = lambda **kw: None  # type: ignore[method-assign]

        from clinkz.models.methodology import SQLiMethodologyResult

        result = SQLiMethodologyResult(candidate_param="id")
        page = PageAnalysis(url="http://t/app/records/", body="", status=200, input_params=["id"])
        await agent._sqli_adapt_context(page, "id", result, {"length": 500, "body": "A" * 500})
        assert result.verified is False


async def _identical() -> _HTTPResponse:
    return _HTTPResponse(status=200, body="A" * 500)


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


def test_restrictions_default_to_no_carrier() -> None:
    """The new field is additive: an existing caller sees the old behaviour."""
    assert FileUploadRestrictions().image_carrier_extension == ""
