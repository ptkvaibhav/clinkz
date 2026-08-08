"""DOM-XSS ranks on an OBSERVED DOM source, not on what the route is called.

Engagement `a2cbcc4d` — a full `clinkz scan` against DVWA — dispatched
`_test_xss_dom` twenty times and reported ``source_sink_pairs=0`` on every one.
The class had never reached the application's DOM-XSS route. It ranked purely on
path words (``javascript``, ``js``, ``client``) that it shared verbatim with
`_test_javascript_attacks`, so a general "javascript" page and a ``.js`` asset
graded ABOVE the one route whose page actually reads ``document.location.href``
into ``document.write`` — and the plan cap then dropped it. The engine's own
RANKING FAILURE check reported 92 inversions and the class still never fired.

Whether a DOM sink is reachable is a property of what the page RETURNED, never
of its name. So it is recorded as an observed response feature, exactly like
``sets_cookies`` and ``has_form``, and the planner ranks on the observation.
"""

from __future__ import annotations

from clinkz.agents._dom_sources import body_reads_dom_source, sink_guard_url_tokens
from clinkz.agents.exploit import _CLASS_PRECONDITIONS, _endpoint_class_relevance
from clinkz.models.scan import Endpoint

# The real DVWA `xss_d` inline block, which is byte-identical at low/medium/high.
DOM_SOURCE_PAGE = (
    "<script>"
    'if (document.location.href.indexOf("default=") >= 0) {'
    '  var lang = document.location.href.substring(document.location.href.indexOf("default=")+8);'
    '  document.write("<option value=\'" + lang + "\'>" + decodeURI(lang) + "</option>");'
    "}</script>"
)


class TestTheSourceDetectorReadsTheResponse:
    def test_a_page_carrying_a_source_and_a_sink_qualifies(self) -> None:
        assert body_reads_dom_source(DOM_SOURCE_PAGE) is True

    def test_an_ordinary_page_is_not(self) -> None:
        assert body_reads_dom_source("<html><body><form></form></body></html>") is False

    def test_an_empty_body_is_not(self) -> None:
        assert body_reads_dom_source("") is False

    def test_the_common_source_sink_shapes_are_covered(self) -> None:
        for js in (
            "<script>document.write(location.hash);</script>",
            "<script>el.innerHTML = document.URL;</script>",
            "<script>eval(window.name)</script>",
            "<script>el.outerHTML = document.referrer;</script>",
        ):
            assert body_reads_dom_source(js) is True, js


class TestThePreconditionMustStaySelective:
    """A precondition true of most of an application starves every other class.

    Measured, not theorised. The source-only version of this predicate shipped
    to engagement `2cf65d36` and cost eleven findings across nine unrelated
    classes: DOM-XSS graded far too many endpoints as its own surface, and the
    global plan cap pushed SQL injection off ``/vulnerabilities/sqli/?id=`` onto
    the login form. Selectivity is the property under test.
    """

    def test_a_source_with_no_sink_does_not_qualify(self) -> None:
        """A shared nav script that reads ``location`` is on every page of a
        real application. Qualifying on that is what did the damage."""
        assert body_reads_dom_source("<script>var p = location.hash;</script>") is False
        assert body_reads_dom_source("<script>if (location.href) hi();</script>") is False

    def test_a_sink_with_no_source_does_not_qualify(self) -> None:
        """A template that writes its own static markup is not a DOM-XSS surface."""
        assert body_reads_dom_source("<script>document.write('<b>hi</b>');</script>") is False
        assert body_reads_dom_source("<script>el.innerHTML = 'static';</script>") is False


class TestTheClassRanksOnTheObservation:
    def test_the_class_declares_the_precondition(self) -> None:
        assert "dom_source" in _CLASS_PRECONDITIONS["_test_xss_dom"]

    def test_an_observed_dom_source_outranks_a_javascript_named_route(self) -> None:
        """The exact inversion from the live run, in both directions."""
        real = Endpoint(
            url="http://t/vulnerabilities/xss_d/?default=English",
            params=["default"],
            has_dom_source=True,
        )
        decoy = Endpoint(url="http://t/vulnerabilities/javascript/")
        asset = Endpoint(url="http://t/dvwa/js/dvwaPage.js")

        real_grade = _endpoint_class_relevance("_test_xss_dom", real)
        assert real_grade < _endpoint_class_relevance("_test_xss_dom", decoy)
        assert real_grade < _endpoint_class_relevance("_test_xss_dom", asset)

    def test_without_the_observation_the_route_does_not_win_on_its_name(self) -> None:
        """A page that merely SITS at an xss-ish path proves nothing — the
        signal has to be the response, or this is just a second path table."""
        unobserved = Endpoint(url="http://t/vulnerabilities/xss_d/", has_dom_source=False)
        observed = Endpoint(url="http://t/anything/at/all", has_dom_source=True)
        assert _endpoint_class_relevance("_test_xss_dom", observed) < _endpoint_class_relevance(
            "_test_xss_dom", unobserved
        )

    def test_the_feature_defaults_off_so_an_unenriched_crawl_ranks_as_before(self) -> None:
        assert Endpoint(url="http://t/x").has_dom_source is False


class TestTheProbeCarriesTheGuardTokenTheSinkRequires:
    """A sink behind a guard is unreachable to a probe that omits its parameter.

    Engagement `f9ddc9b1`: P7 navigated to the bare route nine times with real
    payloads and every one was silent, because the sink sits behind
    ``document.location.href.indexOf("default=") >= 0``. That guard was already
    in the lead's own ``raw_observation`` — the token was read and discarded.
    """

    def test_the_token_is_read_out_of_the_targets_own_script(self) -> None:
        assert sink_guard_url_tokens(DOM_SOURCE_PAGE) == ["default"]

    def test_the_common_guard_shapes_are_covered(self) -> None:
        assert sink_guard_url_tokens("if (location.search.includes('view=')) f();") == ["view"]
        assert sink_guard_url_tokens("location.search.match(/tab=/)") == ["tab"]

    def test_an_unguarded_sink_yields_no_token(self) -> None:
        assert sink_guard_url_tokens("document.write(location.hash)") == []

    def test_a_bare_route_gains_the_token(self) -> None:
        agent = _probe_agent()
        result = _dom_result(DOM_SOURCE_PAGE)
        probe = agent._p7_dom_xss_probe_url("http://t/vulnerabilities/xss_d/", result)
        assert probe == "http://t/vulnerabilities/xss_d/?default=clinkz"

    def test_an_existing_value_is_never_overwritten(self) -> None:
        """The application's own value is the one that works; ours is filler."""
        agent = _probe_agent()
        result = _dom_result(DOM_SOURCE_PAGE)
        url = "http://t/vulnerabilities/xss_d/?default=English"
        assert agent._p7_dom_xss_probe_url(url, result) == url

    def test_a_result_with_no_guard_leaves_the_url_alone(self) -> None:
        agent = _probe_agent()
        assert agent._p7_dom_xss_probe_url("http://t/x/", _dom_result("")) == "http://t/x/"


def _probe_agent():
    import logging

    from clinkz.agents.exploit import ExploitAgent

    agent = ExploitAgent.__new__(ExploitAgent)
    agent._logger = logging.getLogger("probe-test")
    return agent


def _dom_result(script: str):
    from clinkz.models.methodology import DOMSourceSinkPair, DOMXSSMethodologyResult

    pairs = (
        [
            DOMSourceSinkPair(
                source="document.location.href", sink="document.write(", script_excerpt=script
            )
        ]
        if script
        else []
    )
    return DOMXSSMethodologyResult(
        verified=True, verification_strength="likely", source_sink_pairs=pairs
    )


class TestTheVocabularyHasOneDefinition:
    def test_the_methodology_and_the_crawl_read_the_same_patterns(self) -> None:
        """Two copies would let the planner and the methodology disagree about
        what a DOM source is — the planner would rank a page the methodology
        then finds no candidate on, or worse, the reverse."""
        from clinkz.agents._dom_sources import DOM_SOURCE_PATTERNS
        from clinkz.agents.exploit import _DOM_SOURCE_PATTERNS

        assert _DOM_SOURCE_PATTERNS is DOM_SOURCE_PATTERNS
