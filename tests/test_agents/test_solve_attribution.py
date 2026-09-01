"""A solve we cannot point at a finding for is not something we can claim.

``solved_by_testing`` is already the honest count of what this engine's traffic
tripped — the crawl-and-authenticate floor has been subtracted. It is still not a
list of things we can SHOW a client, because a solve is the TARGET's verdict on
our traffic and a finding is ours. All three Juice Shop envelope runs earned
three solves and emitted a finding for two of them; ``forgedFeedback`` is a write
crossing that carries another user's ``UserId`` in a POST body, and no dispatched
class claims it.
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


CHALLENGES: dict[str, dict[str, Any]] = {
    "basketAccessChallenge": {"category": "Broken Access Control"},
    "redirectChallenge": {"category": "Unvalidated Redirects"},
    "forgedFeedbackChallenge": {"category": "Improper Input Validation"},
    "xxeFileDisclosureChallenge": {"category": "XXE"},
    "mysteryChallenge": {"category": "Miscellaneous"},
}


def _report(*titles: str) -> dict[str, Any]:
    return {"findings": [{"title": t, "status": "confirmed"} for t in titles]}


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


class TestAttributeSolves:
    def test_the_envelope_split(self) -> None:
        """The live shape, from all three envelope runs."""
        split = benchmark.attribute_solves(
            ["basketAccessChallenge", "forgedFeedbackChallenge", "redirectChallenge"],
            CHALLENGES,
            _report(
                "Idor — via id parameter (horizontal)",
                "Open Redirect via to parameter (allowlist_bypass)",
            ),
        )
        assert split["solved_attributable"] == ["basketAccessChallenge", "redirectChallenge"]
        assert split["solved_attributable_count"] == 2
        unclaimed = split["solved_target_confirmed_only"]
        assert [row["key"] for row in unclaimed] == ["forgedFeedbackChallenge"]
        assert unclaimed[0]["category"] == "Improper Input Validation"
        assert "_test_mass_assignment" in unclaimed[0]["why"]

    def test_an_unconfirmed_finding_attributes_nothing(self) -> None:
        """A lead is not a claim. Only a confirmed finding can carry a solve."""
        split = benchmark.attribute_solves(
            ["basketAccessChallenge"],
            CHALLENGES,
            {"findings": [{"title": "Idor — via id parameter", "status": "unconfirmed"}]},
        )
        assert split["solved_attributable"] == []
        assert split["solved_target_confirmed_only"][0]["key"] == "basketAccessChallenge"

    def test_a_category_no_class_claims_says_so(self) -> None:
        split = benchmark.attribute_solves(
            ["mysteryChallenge"], CHALLENGES, _report("SQL Injection in q parameter")
        )
        assert split["solved_target_confirmed_only"][0]["why"] == (
            "no dispatched class claims this category"
        )

    def test_an_unmeasured_floor_propagates_as_none(self) -> None:
        """``None`` means unmeasured, and it stays unmeasured. Never zero."""
        split = benchmark.attribute_solves(None, CHALLENGES, _report())
        assert split["solved_attributable"] is None
        assert split["solved_attributable_count"] is None
        assert split["solved_target_confirmed_only"] is None

    def test_an_empty_solved_set_is_a_measurement(self) -> None:
        split = benchmark.attribute_solves([], CHALLENGES, _report())
        assert split["solved_attributable"] == []
        assert split["solved_attributable_count"] == 0
        assert split["solved_target_confirmed_only"] == []

    def test_the_rule_is_stated_in_the_output(self) -> None:
        """The link is by category, and the record must not overclaim it."""
        split = benchmark.attribute_solves(["redirectChallenge"], CHALLENGES, _report())
        assert "not a claim that a particular finding solved" in split["attribution_rule"]
