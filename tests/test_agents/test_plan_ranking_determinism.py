"""D1 batch-5 (G18): the task ranking scores a (class, endpoint) PAIR, deterministically.

Batch 4 measured the defect and left it open. The plan cap dropped ~480 of ~620
candidate tasks per run; relevance grade 2 was a tie bucket holding hundreds of
endpoints; and the tie was broken by the crawl's own emission order, which a
concurrent crawler does not reproduce. So two identical runs against an
unchanged target planned a different 150 tasks, and whether the one endpoint a
class could confirm on survived was close to a coin flip:

  * ``_test_weak_session`` reached ``/vulnerabilities/weak_id/`` in 1 of 3 runs,
  * ``_test_sqli`` reached ``/vulnerabilities/brute/`` in 1 of 3 runs,
  * ``_test_sqli`` reached ``/vulnerabilities/sqli/`` in 0 of 1 HIGH runs.

Three properties are asserted here, and together they are the fix:

  1. **Every class has ranking signals.** Seven had no path-token entry, which
     is not "opting out" — it is ranking on a parameter predicate alone, so
     every endpoint the class cannot read a parameter from lands in one bucket.
  2. **A class's precondition is an OBSERVATION.** A session-token test can only
     measure a page that issues a cookie; a path substring is not that.
  3. **The order is total and input-order-independent.** Shuffling the
     discovered endpoints must not change one task in the plan.
"""

from __future__ import annotations

import logging
import random

import pytest

from clinkz.agents._url_shape import crawl_visit_priority
from clinkz.agents.exploit import (
    _CLASS_PARAM_NAMES,
    _CLASS_PARAM_PREDICATE_NAMES,
    _CLASS_PATH_TOKENS,
    _CLASS_PRECONDITIONS,
    TIER1_TESTS,
    ExploitAgent,
    _endpoint_class_relevance,
    _endpoint_class_sort_key,
    _param_name_tokens,
    _path_names_class_surface,
)
from clinkz.models.finding import ExploitTask
from clinkz.models.scan import Endpoint


def _agent(max_plan_tasks: int = 150) -> ExploitAgent:
    agent = ExploitAgent.__new__(ExploitAgent)
    agent._logger = logging.getLogger("test.plan.ranking")
    agent._max_plan_tasks = max_plan_tasks
    agent._session_headers = {}
    agent._session_cookies = {}
    agent._unproven_exploit_leads = []
    agent._jwt_session_token = lambda: None  # type: ignore[method-assign]
    return agent


def _dvwa_shaped_endpoints() -> list[Endpoint]:
    """The shape the live DVWA runs produced: ~150 endpoints, mostly noise.

    Deliberately built with the noise FIRST, the way the crawl emitted it — a
    ranking that is really ranking must not care.
    """
    eps: list[Endpoint] = []
    for i in range(40):
        eps.append(
            Endpoint(url=f"http://t/app/view_source.php?id=mod{i}", method="GET", params=["id"])
        )
    for i in range(25):
        eps.append(Endpoint(url=f"http://t/app/app/x{i}/source/low.php", method="GET"))
    for i in range(20):
        eps.append(Endpoint(url=f"http://t/static/css/s{i}.css", method="GET"))
    for i in range(30):
        eps.append(Endpoint(url=f"http://t/app/module{i}/", method="GET"))
    eps += [
        # The endpoint the session class must reach: observed to set a cookie.
        Endpoint(url="http://t/app/weak_id/", method="GET", sets_cookies=["appSession"]),
        # A page with a session-shaped PATH that sets nothing — the tie that was
        # being broken by crawl order.
        Endpoint(url="http://t/session.php", method="GET"),
        # The injection family's cross-request vector: no parameter at all.
        Endpoint(
            url="http://t/app/records/",
            method="GET",
            session_setters=["http://t/app/records/session-input.php"],
        ),
        Endpoint(url="http://t/app/exec/", method="POST", params=["ip", "Submit"], has_form=True),
        Endpoint(
            url="http://t/app/upload/", method="POST", params=["file", "Upload"], has_form=True
        ),
        Endpoint(
            url="http://t/app/guestbook/",
            method="POST",
            params=["txtName", "mtxMessage", "btnSign"],
            has_form=True,
        ),
        Endpoint(url="http://t/app/include/?page=home.php", method="GET", params=["page"]),
        Endpoint(
            url="http://t/login.php", method="POST", params=["username", "password"], has_form=True
        ),
    ]
    return eps


# ===========================================================================
# 1 — every class has ranking signals (the data-gap audit, enforced)
# ===========================================================================


class TestEveryClassHasRankingSignals:
    """``_test_sqli`` having no path-token entry was a data gap, not a design
    choice. This asserts the audit result rather than restating it in prose."""

    def test_every_tier1_class_has_a_path_token_entry(self) -> None:
        missing = sorted(m for m in TIER1_TESTS if m not in _CLASS_PATH_TOKENS)
        assert missing == [], f"classes with no _CLASS_PATH_TOKENS entry: {missing}"

    def test_every_tier1_class_has_at_least_one_usable_signal(self) -> None:
        """An entry that is present but empty still ranks nothing. Header hygiene
        is the one class whose target is an ORIGIN rather than a route, so it
        carries a precondition instead of tokens — but it must carry one."""
        unrankable = []
        for method in TIER1_TESTS:
            has_signal = (
                bool(_CLASS_PATH_TOKENS.get(method))
                or bool(_CLASS_PARAM_NAMES.get(method))
                or method in _CLASS_PARAM_PREDICATE_NAMES
                or bool(_CLASS_PRECONDITIONS.get(method))
            )
            if not has_signal:
                unrankable.append(method)
        assert unrankable == [], f"classes with no ranking signal at all: {unrankable}"

    def test_sqli_ranks_its_own_surface_rather_than_only_id_params(self) -> None:
        """The measured HIGH failure: the application takes its id through
        session indirection, so its own page carries no query parameter."""
        login = Endpoint(url="http://t/app/login/", method="POST", params=["username", "password"])
        assert _endpoint_class_relevance("_test_sqli", login) == 0


# ===========================================================================
# 2 — a precondition is an observation, not a path substring
# ===========================================================================


class TestPreconditionsAreObservations:
    def test_a_page_that_sets_a_cookie_outranks_one_that_merely_says_session(self) -> None:
        issues_token = Endpoint(
            url="http://t/app/weak_id/", method="GET", sets_cookies=["appSession"]
        )
        names_itself = Endpoint(url="http://t/session.php", method="GET")
        assert _endpoint_class_relevance("_test_weak_session", issues_token) == 0
        assert _endpoint_class_relevance("_test_weak_session", names_itself) == 1
        assert _endpoint_class_sort_key(
            "_test_weak_session", issues_token
        ) < _endpoint_class_sort_key("_test_weak_session", names_itself)

    def test_a_session_setter_is_an_injection_point_for_the_injection_family(self) -> None:
        """A param-less trigger page whose write reaches the query IS the
        injection point; ranking it on "carries no parameter" is what dropped
        the SQLi endpoint verbatim at HIGH."""
        trigger = Endpoint(
            url="http://t/app/records/",
            method="GET",
            session_setters=["http://t/app/records/session-input.php"],
        )
        assert _endpoint_class_relevance("_test_sqli", trigger) == 0

    def test_an_observed_form_is_the_csrf_precondition(self) -> None:
        """DVWA's password-change form is served over GET, so a method check
        alone misses it — the observation is that the page rendered a form."""
        get_form = Endpoint(url="http://t/app/profile/", method="GET", has_form=True)
        plain = Endpoint(url="http://t/app/blank/", method="GET")
        assert _endpoint_class_relevance("_test_csrf", get_form) == 0
        assert _endpoint_class_relevance("_test_csrf", plain) == 2

    def test_response_features_default_to_not_observed(self) -> None:
        """A target where enrichment never ran must rank exactly as it did
        before the signal existed — additive, never destructive. Uses a path
        that names no class surface, so the default is the only thing measured."""
        bare = Endpoint(url="http://t/app/dashboard/", method="GET")
        assert bare.sets_cookies == []
        assert bare.has_form is False
        assert _endpoint_class_relevance("_test_weak_session", bare) == 2

    def test_a_post_gated_token_issuer_is_still_reachable(self) -> None:
        """The precondition this class most needs is the one a read-only crawl
        cannot see: DVWA issues ``dvwaSession`` inside
        ``if REQUEST_METHOD == "POST"``, so a GET observes no cookie and mapping
        an application must not submit forms to find out. The form the
        submission would go through, plus a path naming an id-issuing route, is
        what remains observable — and it must be enough to rank the endpoint."""
        issuer = Endpoint(url="http://t/app/weak_id/", method="GET", has_form=True)
        assert issuer.sets_cookies == []
        assert _endpoint_class_relevance("_test_weak_session", issuer) == 0

    @pytest.mark.parametrize(
        ("tokens", "path", "expected"),
        [
            # Short tokens match a whole WORD: "a route that issues an id" is a
            # real signal, and /video/ is not one.
            (("id",), "/app/weak_id/", True),
            (("id",), "/app/video/", False),
            (("id",), "/app/idea/", False),
            (("id",), "/app/user/id", True),
            # Longer tokens keep substring matching, so a run-together path
            # still resolves.
            (("file",), "/app/fileupload/", True),
            (("session",), "/app/mysessions/", True),
            ((), "/app/anything/", False),
        ],
    )
    def test_a_short_path_token_matches_a_word_not_a_substring(
        self, tokens: tuple[str, ...], path: str, expected: bool
    ) -> None:
        assert _path_names_class_surface(tokens, path) is expected


class TestParameterNamesMatchTheWordsInside:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("txtName", {"txtname", "txt", "name"}),
            ("mtxMessage", {"mtxmessage", "mtx", "message"}),
            ("password_new", {"password_new", "password", "new"}),
            ("id", {"id"}),
        ],
    )
    def test_subtokens(self, name: str, expected: set[str]) -> None:
        assert _param_name_tokens(name) == expected

    def test_a_prefixed_field_still_matches_its_functional_word(self) -> None:
        guestbook = Endpoint(
            url="http://t/app/guestbook/", method="POST", params=["txtName", "mtxMessage"]
        )
        assert _endpoint_class_relevance("_test_xss_stored", guestbook) == 0

    def test_matching_is_by_word_not_by_substring(self) -> None:
        """``id`` must not match inside ``video`` the way a substring test
        would — the tokens are words, and the match is still exact."""
        assert "id" not in _param_name_tokens("video")


# ===========================================================================
# 3 — the order is total, and independent of the order things were discovered
# ===========================================================================


class TestOrderingIsDeterministic:
    def test_shuffling_the_discovered_endpoints_changes_no_task(self) -> None:
        """The property the whole fix rests on. The endpoint SET was stable
        across the three D1 LOW runs (166 of 172 identical); the ORDER was not,
        diverging by the third entry. A plan that is a function of the set is
        reproducible; one that is a function of the order is not."""
        agent = _agent()
        base = _dvwa_shaped_endpoints()
        reference = agent._build_deterministic_plan(base, [], [])
        reference_keys = [(t.test_method, t.endpoint_url) for t in reference.tasks]

        rng = random.Random(20260731)
        for _ in range(5):
            shuffled = base[:]
            rng.shuffle(shuffled)
            plan = agent._build_deterministic_plan(shuffled, [], [])
            assert [(t.test_method, t.endpoint_url) for t in plan.tasks] == reference_keys

    def test_endpoint_pre_ranking_is_also_order_independent(self) -> None:
        """The pre-rank feeds the LLM planning prompt's top-N window; if it
        varies, the LLM's own plan varies with it."""
        agent = _agent()
        base = _dvwa_shaped_endpoints()
        reference = [e.url for e in agent._dedupe_and_rank_endpoints(base)]
        rng = random.Random(7)
        for _ in range(5):
            shuffled = base[:]
            rng.shuffle(shuffled)
            assert [e.url for e in agent._dedupe_and_rank_endpoints(shuffled)] == reference

    def test_each_class_reaches_the_endpoint_it_can_actually_fire_on(self) -> None:
        """The end-to-end assertion, under the real cap: the endpoint carrying
        each class's own surface is IN the plan, not merely a task for it."""
        agent = _agent()
        plan = agent._build_deterministic_plan(_dvwa_shaped_endpoints(), [], [])
        planned = {(t.test_method, t.endpoint_url) for t in plan.tasks}
        for method, prefix in (
            ("_test_weak_session", "http://t/app/weak_id/"),
            ("_test_sqli", "http://t/app/records/"),
            ("_test_cmdi", "http://t/app/exec/"),
            ("_test_file_upload", "http://t/app/upload/"),
            ("_test_xss_stored", "http://t/app/guestbook/"),
            ("_test_lfi", "http://t/app/include/"),
        ):
            assert any(m == method and url.startswith(prefix) for m, url in planned), (
                f"{method} never reached {prefix}"
            )


class TestCrawlVisitPriority:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("http://t/app/fi/?page=x", 0),
            ("http://t/app/brute/", 1),
            ("http://t/app/view_source.php", 2),
            ("http://t/docs/README.md", 3),
            ("http://t/static/main.css", 4),
            ("http://t/app/app/x/", 5),
        ],
    )
    def test_grades(self, url: str, expected: int) -> None:
        assert crawl_visit_priority(url) == expected

    def test_application_pages_are_opened_before_assets(self) -> None:
        """The enrichment budget is 80 visits against ~154 discovered URLs, and
        which 80 used to be "whichever the crawler emitted first". The DVWA
        brute-force page's login form was enriched in 2 of 3 identical runs
        because of it."""
        urls = [
            "http://t/static/a.css",
            "http://t/app/app/dup/",
            "http://t/docs/README.md",
            "http://t/app/brute/",
            "http://t/app/fi/?page=x",
            "http://t/app/view_source.php?id=1",
        ]
        ordered = sorted(urls, key=lambda u: (crawl_visit_priority(u), u))
        assert ordered[:2] == ["http://t/app/fi/?page=x", "http://t/app/brute/"]
        assert ordered[-1] == "http://t/app/app/dup/"


# ===========================================================================
# Ranking failures are named out loud
# ===========================================================================


class TestRankingFailureIsLoud:
    def test_a_dropped_class_surface_is_reported_as_a_ranking_failure(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Truncation removing a tail is the budget working. Truncation removing
        an endpoint where the class's own surface was OBSERVED, while endpoints
        nothing pointed at survive, is the ordering failing — a different defect
        with a different fix, so it gets its own line."""
        agent = _agent(max_plan_tasks=4)
        surface = Endpoint(url="http://t/app/weak_id/", method="GET", sets_cookies=["s"])
        bland = Endpoint(url="http://t/app/plain/", method="GET")
        by_key = {
            agent._endpoint_structural_key(surface): surface,
            agent._endpoint_structural_key(bland): bland,
        }
        dropped_task = ExploitTask(
            test_method="_test_weak_session", endpoint_url=surface.url, tier=1
        )
        kept_task = ExploitTask(test_method="_test_weak_session", endpoint_url=bland.url, tier=1)
        with caplog.at_level(logging.WARNING, logger="test.plan.ranking"):
            agent._log_plan_truncation(
                "deterministic",
                {"_test_weak_session": [kept_task, dropped_task]},
                [kept_task],
                4,
                by_key,
            )
        assert "RANKING FAILURE" in caplog.text
        assert "weak_id" in caplog.text

    def test_dropping_a_tail_is_not_reported_as_a_ranking_failure(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        agent = _agent(max_plan_tasks=4)
        surface = Endpoint(url="http://t/app/weak_id/", method="GET", sets_cookies=["s"])
        bland = Endpoint(url="http://t/app/plain/", method="GET")
        by_key = {
            agent._endpoint_structural_key(surface): surface,
            agent._endpoint_structural_key(bland): bland,
        }
        kept_task = ExploitTask(test_method="_test_weak_session", endpoint_url=surface.url, tier=1)
        dropped_task = ExploitTask(test_method="_test_weak_session", endpoint_url=bland.url, tier=1)
        with caplog.at_level(logging.WARNING, logger="test.plan.ranking"):
            agent._log_plan_truncation(
                "deterministic",
                {"_test_weak_session": [kept_task, dropped_task]},
                [kept_task],
                4,
                by_key,
            )
        assert "TRUNCATED" in caplog.text
        assert "RANKING FAILURE" not in caplog.text
