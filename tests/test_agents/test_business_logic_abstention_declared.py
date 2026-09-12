"""A business-logic class that could not begin says so, and says it correctly.

Measured across every stored trace before this existed:

| skill | phase-1 events | phase-5 verdicts |
|---|---|---|
| `business_logic_single_use_action` | 102 | **0** |
| `business_logic_ordering_constraint` | 62 | **0** |
| `business_logic_quantity_bound` | 50 | 18 |

164 dispatches that reached no verdict, no finding and no lead, and nothing in any
deliverable saying the class had been unable to begin — while all three declare
`capability=SERVER_SIDE`, which the report renders as a statement that the class's
effect is confirmable in-band. *Registered, dispatched, and never able to start*
is its own state.

It is `InconclusiveMeasurement` and deliberately neither of the two neighbours:

* **not a lead** — a lead claims the class could not PROVE something it suspects.
  This class suspects nothing: it could not evidence the application's intent,
  which is the one thing the family is built to refuse to guess at. 164 leads
  reading "candidate single-use action replayed" against every action endpoint on
  every target is the permanent false alarm invariant 77 exists to prevent.
* **not `not_applicable`** — the endpoint may well be single-use. The engine could
  not tell, and a zero measured over part of the input is INDETERMINATE, never NOT
  APPLICABLE (invariant 101).
"""

from __future__ import annotations

from typing import Any

import pytest

from clinkz.agents.report import ReportAgent
from clinkz.models.report import NotTestedCategory


def _report_agent() -> Any:
    """A report agent with no dependencies wired.

    ``_build_not_tested`` reads only its arguments; constructing a real agent
    would drag an LLM client into a test about one rendered sentence.
    """
    return ReportAgent.__new__(ReportAgent)


class _Page:
    """The two attributes the abstention recorder reads."""

    def __init__(self, url: str) -> None:
        self.url = url
        self.input_params: list[str] = []


@pytest.fixture
def agent() -> Any:
    """An exploit agent with only the state the recorder touches.

    Built by hand rather than through the constructor: the recorder is a pure
    append to one list, and a full agent would drag an engagement, a resolver and
    an LLM client into a test about one disclosure.
    """
    from clinkz.agents.exploit import ExploitAgent

    instance = ExploitAgent.__new__(ExploitAgent)
    instance._inconclusive_measurements = []
    return instance


def test_the_phase_one_abstention_is_recorded(agent: Any) -> None:
    """The gate that produced 164 silences now produces a declaration."""
    from clinkz.agents._business_logic import IntentFacet

    agent._record_intent_abstention(
        test_method="_test_repeatability",
        page=_Page("http://target.test/rest/basket/1/checkout"),
        facet=IntentFacet.SINGLE_USE_ACTION,
        records_observed=0,
    )

    assert len(agent._inconclusive_measurements) == 1
    measurement = agent._inconclusive_measurements[0]
    assert measurement.test_method == "_test_repeatability"
    assert measurement.endpoint == "http://target.test/rest/basket/1/checkout"
    assert "single_use_action" in measurement.reason
    assert "0 record(s)" in measurement.reason
    # One request went out — the representation read. Not eight, and not zero:
    # "could not conclude" reads differently at each.
    assert measurement.attempts == 1


def test_the_reason_carries_the_record_count(agent: Any) -> None:
    """ "Could not evidence the intent" reads differently at 0 records and at 5.

    One recorded Juice Shop dispatch is exactly this case: `/rest/image-captcha/:id`
    returned a record and still evidenced nothing, because a record carrying no
    consumption-marker field name evidences nothing. The gate is the evidence, not
    the fetch, and the disclosure has to be able to say which.
    """
    from clinkz.agents._business_logic import IntentFacet

    agent._record_intent_abstention(
        test_method="_test_repeatability",
        page=_Page("http://target.test/rest/image-captcha/1"),
        facet=IntentFacet.SINGLE_USE_ACTION,
        records_observed=1,
    )
    assert "1 record(s)" in agent._inconclusive_measurements[0].reason


def test_it_renders_as_not_tested_without_asserting_a_control_arm() -> None:
    """The shared row states the producer's mechanism, not brute-force's.

    The renderer used to say "its own positive control refused the series" for
    every producer in this category. That is true of the brute-force series and
    false of this one, which sends no probe at all — a shared rendering asserting
    one caller's mechanism about another's evidence.
    """
    items = ReportAgent._build_not_tested(
        _report_agent(),
        engagement_id="abstention-test",
        authorization=None,
        scope_out=[],
        safety={},
        authentication={},
        finding_count=0,
        graybox_source={},
        resumed_from="",
        client_oracle={},
        inconclusive_measurements=[
            {
                "test_method": "_test_repeatability",
                "endpoint": "http://target.test/rest/basket/1/checkout",
                "reason": "the application's own surface evidenced no single_use_action "
                "for this endpoint",
                "attempts": 1,
            }
        ],
        credential_sweep={},
    )
    rows = [i for i in items if i.category is NotTestedCategory.MEASUREMENT_INCONCLUSIVE]
    assert len(rows) == 1
    assert "positive control" not in rows[0].reason
    assert "could support no conclusion" in rows[0].reason
    assert "evidenced no single_use_action" in rows[0].reason
    assert "absence of a measurement, not the absence of a flaw" in rows[0].reason


def test_identical_abstentions_collapse_into_one_row() -> None:
    """41 near-identical paragraphs is a section a reader learns to skip.

    Grouped by (class, reason) with every endpoint named inside the row, so the
    explanation is not repeated and nothing is dropped.
    """
    reason = "the application's own surface evidenced no single_use_action for this endpoint"
    measurements = [
        {
            "test_method": "_test_repeatability",
            "endpoint": f"http://target.test/rest/action/{i}",
            "reason": reason,
            "attempts": 1,
        }
        for i in range(41)
    ]
    items = ReportAgent._build_not_tested(
        _report_agent(),
        engagement_id="abstention-test",
        authorization=None,
        scope_out=[],
        safety={},
        authentication={},
        finding_count=0,
        graybox_source={},
        resumed_from="",
        client_oracle={},
        inconclusive_measurements=measurements,
        credential_sweep={},
    )
    rows = [i for i in items if i.category is NotTestedCategory.MEASUREMENT_INCONCLUSIVE]
    assert len(rows) == 1, "41 identical reasons must not produce 41 rows"
    assert "41 endpoint(s)" in rows[0].item
    # The total attempt count stays exact even though the endpoint list is bounded.
    assert "41 request(s)" in rows[0].reason
    assert "29 more" in rows[0].reason


def test_a_different_reason_keeps_its_own_row() -> None:
    """Grouping never merges two different explanations."""
    items = ReportAgent._build_not_tested(
        _report_agent(),
        engagement_id="abstention-test",
        authorization=None,
        scope_out=[],
        safety={},
        authentication={},
        finding_count=0,
        graybox_source={},
        resumed_from="",
        client_oracle={},
        inconclusive_measurements=[
            {
                "test_method": "_test_brute_force",
                "endpoint": "http://target.test/login",
                "reason": "8 of 8 attempts never reached the authentication handler",
                "attempts": 8,
            },
            {
                "test_method": "_test_repeatability",
                "endpoint": "http://target.test/rest/basket/1/checkout",
                "reason": "no single_use_action was evidenced",
                "attempts": 1,
            },
        ],
        credential_sweep={},
    )
    rows = [i for i in items if i.category is NotTestedCategory.MEASUREMENT_INCONCLUSIVE]
    assert len(rows) == 2
    assert {row.item.split(" at ")[0] for row in rows} == {
        "_test_brute_force",
        "_test_repeatability",
    }


class TestWhoseLimitationIsIt:
    """R13: the abstention has to say when the cause is the ENGINE, not the target.

    The reason above is a statement about the endpoint — *its surface evidenced
    nothing here*. For two of the three facets that is not the whole truth. With
    no collection representation, the only remaining evidence source is the
    rejection pool, and the pool is written by ``_remember_rejection`` at phase 3
    — downstream of the phase-1 gate it is needed to pass. The check therefore
    cannot pass on an endpoint of that shape whatever the application does, and a
    reader told only the first sentence goes looking at their own application.

    ``QUANTITY_BOUND`` is excluded deliberately: it is evidenced from a
    collection's representation, which is upstream of every gate, and it is the
    one facet of the three that has ever reached a verdict.
    """

    @pytest.mark.parametrize(
        "facet_name",
        ["SINGLE_USE_ACTION", "ORDERING_CONSTRAINT"],
    )
    def test_a_structural_abstention_names_the_engine(self, agent: Any, facet_name: str) -> None:
        from clinkz.agents._business_logic import IntentFacet

        agent._record_intent_abstention(
            test_method="_test_repeatability",
            page=_Page("http://target.test/rest/basket/1/checkout"),
            facet=getattr(IntentFacet, facet_name),
            records_observed=0,
        )
        reason = agent._inconclusive_measurements[0].reason
        assert "a limit of the test, not a reading of the endpoint" in reason
        assert "AFTER this check has passed" in reason

    def test_a_representation_that_answered_is_a_reading_of_the_endpoint(self, agent: Any) -> None:
        """With records in hand the class DID read the surface and found nothing.

        The engine-limit sentence would be false here: the evidence source was
        available and answered. One recorded Juice Shop dispatch is this case.
        """
        from clinkz.agents._business_logic import IntentFacet

        agent._record_intent_abstention(
            test_method="_test_repeatability",
            page=_Page("http://target.test/rest/image-captcha/1"),
            facet=IntentFacet.SINGLE_USE_ACTION,
            records_observed=1,
        )
        assert "a limit of the test" not in agent._inconclusive_measurements[0].reason

    def test_the_quantity_bound_facet_never_claims_the_engine_limit(self, agent: Any) -> None:
        """The facet that works reads an upstream source and must not borrow this."""
        from clinkz.agents._business_logic import IntentFacet

        agent._record_intent_abstention(
            test_method="_test_constraint_violation",
            page=_Page("http://target.test/rest/products"),
            facet=IntentFacet.QUANTITY_BOUND,
            records_observed=0,
        )
        assert "a limit of the test" not in agent._inconclusive_measurements[0].reason
