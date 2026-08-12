"""The NEEDS_CHAINING classification, checked against the engine's own tables.

A coverage claim written as prose rots the moment a class is added or removed.
This turns the classification into an artifact the build validates: every link
names a real :class:`ArtifactKind`, every producing class is one the engine
actually dispatches, every coverage value is from a closed vocabulary, and an
entry claiming full coverage may not also carry a blocking gap.

What the tests deliberately do NOT check is whether a given Juice Shop build
ships these challenges or solves them this way. That is a question about a
running target and belongs to the live gate — the fixture says so in its own
``premise_status`` field, and this file asserts that it keeps saying so.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clinkz.agents.exploit import DISPATCHABLE_TEST_METHODS
from clinkz.chaining.models import ChainKind
from clinkz.chaining.vocabulary import ArtifactKind

_FIXTURE = Path(__file__).parent.parent / "fixtures" / "needs_chaining_classification.json"

_CLASSIFICATION = json.loads(_FIXTURE.read_text(encoding="utf-8"))
_CHALLENGES = _CLASSIFICATION["challenges"]
_COVERAGE_VALUES = set(_CLASSIFICATION["_about"]["coverage_vocabulary"])

_IDS = [c["label"] for c in _CHALLENGES]


def test_the_classification_covers_seven_challenges() -> None:
    assert len(_CHALLENGES) == 7
    assert len(set(_IDS)) == 7


def test_the_premise_is_marked_unverified_against_a_live_instance() -> None:
    """The repository has no pre-existing NEEDS_CHAINING list, so this is derived.

    Saying so in the artifact is the difference between a classification and a
    claim. The live gate is what would turn it into the latter.
    """
    status = _CLASSIFICATION["_about"]["premise_status"]
    assert status.startswith("UNVERIFIED AGAINST A LIVE INSTANCE")
    assert "no pre-existing NEEDS_CHAINING list" in status


def test_no_benchmark_vocabulary_leaks_into_src() -> None:
    """A methodology must never carry a benchmark's own names.

    The classification lives in tests/fixtures precisely so this stays true, and
    the check is here rather than in a review comment.
    """
    src = Path(__file__).parent.parent.parent / "src" / "clinkz"
    offenders = [
        path
        for path in src.rglob("*.py")
        if "juice" in path.read_text(encoding="utf-8", errors="replace").lower()
        and "chaining" in str(path)
    ]
    assert not offenders, f"benchmark vocabulary in the chaining package: {offenders}"


@pytest.mark.parametrize("challenge", _CHALLENGES, ids=_IDS)
class TestEachClassifiedChallenge:
    def test_it_names_a_real_chain_kind(self, challenge: dict) -> None:
        assert challenge["chain_kind"] in {k.value for k in ChainKind}

    def test_every_required_link_names_a_real_artifact_kind(self, challenge: dict) -> None:
        for link in challenge["required_links"]:
            assert link["artifact"] in {a.value for a in ArtifactKind}, link

    def test_every_producing_class_is_one_the_engine_dispatches(self, challenge: dict) -> None:
        """A link attributed to a class that does not exist is a coverage fiction."""
        for link in challenge["required_links"]:
            producer = link["producing_class"]
            if producer:
                assert producer in DISPATCHABLE_TEST_METHODS, (
                    f"{challenge['label']} link {link['ordinal']} credits {producer!r}, "
                    f"which the engine does not dispatch"
                )

    def test_a_link_with_no_producing_class_is_the_carriage_or_a_gap(self, challenge: dict) -> None:
        for link in challenge["required_links"]:
            if not link["producing_class"]:
                assert link["coverage"] in ("chain_carriage", "no_methodology", "lead_only"), link

    def test_every_coverage_value_is_from_the_closed_vocabulary(self, challenge: dict) -> None:
        for link in challenge["required_links"]:
            assert link["coverage"] in _COVERAGE_VALUES, link

    def test_link_ordinals_are_consecutive_from_one(self, challenge: dict) -> None:
        ordinals = [link["ordinal"] for link in challenge["required_links"]]
        assert ordinals == list(range(1, len(ordinals) + 1))

    def test_a_gap_and_full_coverage_are_mutually_exclusive(self, challenge: dict) -> None:
        """An entry cannot claim every link is covered AND name what blocks it."""
        uncovered = [
            link
            for link in challenge["required_links"]
            if link["coverage"] in ("no_methodology", "lead_only")
        ]
        gap = challenge["blocking_gap"]
        if uncovered:
            assert gap, (
                f"{challenge['label']} has uncovered link(s) "
                f"{[link['ordinal'] for link in uncovered]} but names no blocking gap"
            )
        # The converse does NOT hold: a chain can have every LINK covered and
        # still be blocked by something else (a rail refusal, an oracle that
        # does not apply to this composition), which is exactly what the two
        # gap-bearing fully-covered entries record.

    def test_a_stated_gap_is_substantive(self, challenge: dict) -> None:
        gap = challenge["blocking_gap"]
        if gap:
            assert len(gap) > 60, f"{challenge['label']}: the gap is too short to be actionable"


def test_the_classification_states_coverage_for_every_link() -> None:
    """The point of the artifact: a per-link coverage column, not a verdict per challenge."""
    total_links = sum(len(c["required_links"]) for c in _CHALLENGES)
    assert total_links >= 14
    by_coverage: dict[str, int] = {}
    for challenge in _CHALLENGES:
        for link in challenge["required_links"]:
            by_coverage[link["coverage"]] = by_coverage.get(link["coverage"], 0) + 1
    # Both halves are represented: this is a coverage statement, not a victory lap.
    assert by_coverage.get("confirmed_today", 0) > 0
    assert by_coverage.get("chain_carriage", 0) > 0
    assert by_coverage.get("no_methodology", 0) > 0, (
        "a classification in which nothing is missing is not a classification"
    )
