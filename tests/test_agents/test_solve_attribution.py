"""A solve we cannot point at a finding for is not something we can claim.

``solved_by_testing`` is already the honest count of what this engine's traffic
tripped — the crawl-and-authenticate floor has been subtracted. It is still not a
list of things we can SHOW a client, because a solve is the TARGET's verdict on
our traffic and a finding is ours. All three Juice Shop envelope runs earned
three solves and emitted a finding for two of them; ``forgedFeedback`` is a write
crossing that carries another user's ``UserId`` in a POST body, and no dispatched
class claims it.

**And the claim is bound to a FINDING, not to a class.** Run 3 emitted
``_test_idor`` findings at ``/rest/basket/:id`` and at ``/api/Users/:p3``, so
``basketAccess`` read as attributable from either — and removing the basket
finding, the one the challenge is actually about, left the positive reading
standing on a sibling of the same class. A positive reading that outlives its own
evidence is a phantom wearing a category label; the class-level test below is the
one that failed to notice, and :class:`TestTheBindingIsToAFinding` is the one
that would.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "_juiceshop_benchmark_run", Path("scripts/juiceshop_benchmark_run.py")
)
assert _SPEC is not None and _SPEC.loader is not None
benchmark = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(benchmark)


#: The categories are the live target's own, not a convenient fiction:
#: ``forgedFeedbackChallenge`` is filed by Juice Shop under Broken Access
#: Control, which maps to ``_test_idor`` — so under the category-only rule ANY
#: confirmed IDOR finding claimed it, including the read crossing at
#: ``/api/Feedbacks/2`` that has nothing to do with posting feedback as someone
#: else. The earlier fixture said "Improper Input Validation", which is what the
#: challenge is SHAPED like and not what the target says.
CHALLENGES: dict[str, dict[str, Any]] = {
    "basketAccessChallenge": {"category": "Broken Access Control"},
    "redirectChallenge": {"category": "Unvalidated Redirects"},
    "forgedFeedbackChallenge": {"category": "Broken Access Control"},
    "loginAdminChallenge": {"category": "Injection"},
    "loginJimChallenge": {"category": "Injection"},
    "xxeFileDisclosureChallenge": {"category": "XXE"},
    "mysteryChallenge": {"category": "Miscellaneous"},
}

BASE = "http://clinkz-juiceshop:3000"

#: The three IDOR findings run 3 actually emitted, by their own targets.
BASKET_IDOR = ("Idor — via id parameter (horizontal)", f"{BASE}/rest/basket/:id")
USERS_IDOR = ("Idor — via p3 parameter (horizontal)", f"{BASE}/api/Users/:p3")
FEEDBACKS_IDOR = ("Idor — via p3 parameter (horizontal)", f"{BASE}/api/Feedbacks/:p3")
REDIRECT = (
    "Open Redirect via to parameter (allowlist_bypass)",
    "http://172.20.0.2:3000/redirect?to=http",
)


def _report(*findings: tuple[str, str], status: str = "confirmed") -> dict[str, Any]:
    return {
        "findings": [{"title": t, "target": u, "status": status} for t, u in findings],
    }


class TestCategoryMapIsInSync:
    def test_both_directions_and_every_method_dispatches(self) -> None:
        """The guard-domain law: the domain is COMPUTED, not restated.

        A category added to ``CATEGORY_ADDRESSABLE`` without classes here would
        be permanently unattributable, which reads exactly like an engine that
        never claims it.
        """
        benchmark._assert_category_classes()

    def test_an_unknown_method_is_a_loud_failure(self, monkeypatch: Any) -> None:
        monkeypatch.setitem(benchmark.CATEGORY_CLASSES, "XXE", ("_test_not_a_real_class",))
        with pytest.raises(AssertionError, match="does not"):
            benchmark._assert_category_classes()

    def test_a_missing_category_is_a_loud_failure(self, monkeypatch: Any) -> None:
        trimmed = {k: v for k, v in benchmark.CATEGORY_CLASSES.items() if k != "XXE"}
        monkeypatch.setattr(benchmark, "CATEGORY_CLASSES", trimmed)
        with pytest.raises(AssertionError, match="out of sync"):
            benchmark._assert_category_classes()


class TestSurfaceShape:
    """What varies without the surface varying is normalised away."""

    def test_a_template_placeholder_and_its_concrete_value_are_one_surface(self) -> None:
        """``:id`` / ``:p3`` / ``2`` are three spellings of one route.

        The placeholder name is whichever discoverer found the route — the
        defect that gave ``/rest/basket/:id`` and ``/rest/basket/:p3`` from one
        crossing — and the arms dispatch the concrete value.
        """
        shapes = {
            benchmark.surface_shape(f"{BASE}/rest/basket/:id"),
            benchmark.surface_shape(f"{BASE}/rest/basket/:p3"),
            benchmark.surface_shape(f"{BASE}/rest/basket/2"),
        }
        assert shapes == {"/rest/basket/*"}

    def test_one_service_under_two_names_is_one_surface(self) -> None:
        """The origin varies without the route varying (``OriginIdentity``)."""
        assert benchmark.surface_shape(f"{BASE}/redirect?to=http") == benchmark.surface_shape(
            "http://172.20.0.2:3000/redirect"
        )

    def test_a_collection_is_not_its_items(self) -> None:
        """The distinction ``forgedFeedback`` turns on."""
        assert benchmark.surface_shape(f"{BASE}/api/Feedbacks") == "/api/feedbacks"
        assert benchmark.surface_shape(f"{BASE}/api/Feedbacks/2") == "/api/feedbacks/*"


class TestChallengeSurfacesTable:
    def test_a_stale_entry_is_a_loud_failure(self) -> None:
        """An entry that outlived the challenge it described attributes nothing
        and hides that it attributes nothing."""
        with pytest.raises(AssertionError, match="does not ship"):
            benchmark._assert_challenge_surfaces({"redirectChallenge": {}})

    def test_every_declared_surface_carries_the_words_that_source_it(self) -> None:
        """The route is ours; the sentence justifying it is the challenge's.

        A table of routes with no sourcing is a table of assertions, and this one
        decides whether a client-facing number goes up.
        """
        for key, (paths, source) in benchmark.CHALLENGE_SURFACES.items():
            assert paths, key
            assert all(p == benchmark.surface_shape(p) for p in paths), key
            assert len(source) > 40, key


class TestTheBindingIsToAFinding:
    """The test the class-level rule could not have failed."""

    def test_removing_the_finding_removes_the_claim(self) -> None:
        """``basketAccess`` with only the sibling ``_test_idor`` finding left.

        The corrected anchored oracle refutes run 3's ``/rest/basket/:id``
        finding and keeps its ``/api/Users/:p3`` one. Both resolve to
        ``_test_idor`` and Broken Access Control maps to that class, so under the
        category-only rule the solve stayed attributable across a change that
        removed the evidence for it.
        """
        with_basket = benchmark.attribute_solves(
            ["basketAccessChallenge"], CHALLENGES, _report(BASKET_IDOR, USERS_IDOR)
        )
        assert with_basket["solved_attributable"] == ["basketAccessChallenge"]

        without_basket = benchmark.attribute_solves(
            ["basketAccessChallenge"], CHALLENGES, _report(USERS_IDOR)
        )
        assert without_basket["solved_attributable"] == []
        row = without_basket["solved_target_confirmed_only"][0]
        assert row["key"] == "basketAccessChallenge"
        assert "/rest/basket/*" in row["why"]
        assert "/api/users/*" in row["why"]

    def test_the_bound_finding_is_named(self) -> None:
        """A claim a reader can check against the findings list."""
        split = benchmark.attribute_solves(
            ["basketAccessChallenge"], CHALLENGES, _report(BASKET_IDOR, USERS_IDOR)
        )
        (evidence,) = split["solved_attributable_evidence"]
        assert evidence["key"] == "basketAccessChallenge"
        assert evidence["challenge_surface"] == ["/rest/basket/*"]
        assert [f["target"] for f in evidence["findings"]] == [f"{BASE}/rest/basket/:id"]
        assert evidence["findings"][0]["class"] == "_test_idor"
        assert "shopping basket" in evidence["surface_source"]

    def test_a_read_crossing_on_an_item_does_not_claim_a_write_on_the_collection(
        self,
    ) -> None:
        """``forgedFeedback`` is Broken Access Control on the LIVE target, so the
        category alone binds it to every confirmed IDOR finding — including the
        read crossing run 3 emitted at ``/api/Feedbacks/2``, which is not posting
        feedback in someone else's name."""
        split = benchmark.attribute_solves(
            ["forgedFeedbackChallenge"], CHALLENGES, _report(FEEDBACKS_IDOR)
        )
        assert split["solved_attributable"] == []
        row = split["solved_target_confirmed_only"][0]
        assert "/api/feedbacks" in row["why"]
        assert "/api/feedbacks/*" in row["why"]


class TestAttributeSolves:
    def test_the_envelope_split(self) -> None:
        """The live shape, from all three envelope runs."""
        split = benchmark.attribute_solves(
            ["basketAccessChallenge", "forgedFeedbackChallenge", "redirectChallenge"],
            CHALLENGES,
            _report(BASKET_IDOR, FEEDBACKS_IDOR, REDIRECT),
        )
        assert split["solved_attributable"] == ["basketAccessChallenge", "redirectChallenge"]
        assert split["solved_attributable_count"] == 2
        unclaimed = split["solved_target_confirmed_only"]
        assert [row["key"] for row in unclaimed] == ["forgedFeedbackChallenge"]
        assert unclaimed[0]["category"] == "Broken Access Control"

    def test_an_unconfirmed_finding_attributes_nothing(self) -> None:
        """A lead is not a claim. Only a confirmed finding can carry a solve."""
        split = benchmark.attribute_solves(
            ["basketAccessChallenge"], CHALLENGES, _report(BASKET_IDOR, status="unconfirmed")
        )
        assert split["solved_attributable"] == []
        assert split["solved_target_confirmed_only"][0]["key"] == "basketAccessChallenge"

    def test_a_category_no_class_claims_says_so(self) -> None:
        split = benchmark.attribute_solves(
            ["mysteryChallenge"],
            CHALLENGES,
            _report(("SQL Injection in q parameter", f"{BASE}/rest/products/search")),
        )
        assert split["solved_target_confirmed_only"][0]["why"] == (
            "no dispatched class claims this category"
        )

    def test_an_undeclared_surface_is_unattributable_whatever_was_emitted(self) -> None:
        """The safe direction, stated in the reason so the fix is one entry."""
        split = benchmark.attribute_solves(
            ["xxeFileDisclosureChallenge"],
            CHALLENGES,
            _report(("XXE — external entity", f"{BASE}/api/upload")),
        )
        assert split["solved_attributable"] == []
        assert "no surface is declared" in split["solved_target_confirmed_only"][0]["why"]

    def test_a_class_that_emitted_nothing_says_that_instead(self) -> None:
        """Three reasons, three different fixes: no class, no surface, no finding."""
        split = benchmark.attribute_solves(["basketAccessChallenge"], CHALLENGES, _report())
        why = split["solved_target_confirmed_only"][0]["why"]
        assert "emitted no confirmed finding this run" in why

    def test_an_unmeasured_floor_propagates_as_none(self) -> None:
        """``None`` means unmeasured, and it stays unmeasured. Never zero."""
        split = benchmark.attribute_solves(None, CHALLENGES, _report())
        assert split["solved_attributable"] is None
        assert split["solved_attributable_count"] is None
        assert split["solved_attributable_evidence"] is None
        assert split["solved_target_confirmed_only"] is None

    def test_an_empty_solved_set_is_a_measurement(self) -> None:
        split = benchmark.attribute_solves([], CHALLENGES, _report())
        assert split["solved_attributable"] == []
        assert split["solved_attributable_count"] == 0
        assert split["solved_target_confirmed_only"] == []

    def test_the_rule_is_stated_in_the_output(self) -> None:
        """The link is to a finding on a named surface, and the record must not
        overclaim it as proof that this finding solved this challenge."""
        split = benchmark.attribute_solves(["redirectChallenge"], CHALLENGES, _report())
        rule = split["attribution_rule"]
        assert "dispatched against the surface that challenge names" in rule
        assert "not a claim that a particular finding solved" in rule
