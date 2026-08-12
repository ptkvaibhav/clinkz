"""The chaining vocabulary is the substrate — so it has to be complete.

A class silently absent from both :data:`CLASS_YIELDS` and
:data:`NO_YIELD_REASON` would be invisible to chaining forever: it could never
begin a chain, and nothing would say so. That is the silent-degradation shape the
contribution ledger exists to catch, one layer up, and it is cheaper to catch it
here.
"""

from __future__ import annotations

import pytest

from clinkz.agents.exploit import DISPATCHABLE_TEST_METHODS
from clinkz.chaining.composition import CONFIRMATION_PRIMITIVES
from clinkz.chaining.vocabulary import (
    CLASS_CONFIRMATION_PRIMITIVES,
    CLASS_REQUIRES,
    CLASS_YIELDS,
    NO_YIELD_REASON,
    ArtifactKind,
    can_follow,
    confirmation_primitives_of,
    requires_of,
    yields_of,
)


def test_every_dispatchable_class_is_accounted_for() -> None:
    """A class either declares a yield or says, substantively, why it has none."""
    unaccounted = sorted(
        method
        for method in DISPATCHABLE_TEST_METHODS
        if method not in CLASS_YIELDS and method not in NO_YIELD_REASON
    )
    assert not unaccounted, (
        f"these classes are invisible to chaining and nothing says why: {unaccounted}. "
        f"Add a CLASS_YIELDS entry, or a NO_YIELD_REASON entry stating what the class's "
        f"confirmation actually proves and why that is not an artifact."
    )


def test_a_class_cannot_both_yield_and_declare_it_yields_nothing() -> None:
    """The two tables partition; an entry in both is a contradiction."""
    both = sorted(set(CLASS_YIELDS) & set(NO_YIELD_REASON))
    assert not both, f"declared in both CLASS_YIELDS and NO_YIELD_REASON: {both}"


@pytest.mark.parametrize("method", sorted(NO_YIELD_REASON))
def test_a_no_yield_reason_is_substantive(method: str) -> None:
    """'No yield' is a coverage claim, so the reason has to survive review."""
    reason = NO_YIELD_REASON[method]
    assert len(reason) > 80, f"{method}: the reason is too short to be a real justification"
    assert reason[0].isupper() and reason.rstrip().endswith("."), (
        f"{method}: the reason has to read as prose a reviewer can argue with"
    )


def test_xss_declares_no_yield_because_execution_is_not_a_token() -> None:
    """The load-bearing case: what a class is FAMOUS for is not what it proves.

    Reflected XSS is *about* stealing a session. This engine witnesses script
    execution and never exfiltrates a token, so declaring SESSION_TOKEN here
    would make every XSS finding the head of a chain whose next link could not
    be carried — a chain that cannot be carried cannot be falsified.
    """
    for method in ("_test_xss_reflected", "_test_xss_stored", "_test_xss_dom"):
        assert yields_of(method) == ()
        assert "exfiltrate" in NO_YIELD_REASON[method] or "recovered" in NO_YIELD_REASON[method]


def test_every_class_that_yields_also_names_a_confirmation_primitive() -> None:
    """A link that cannot name its oracle cannot be a confirmed chain link."""
    for method in CLASS_YIELDS:
        cited = confirmation_primitives_of(method)
        assert cited, f"{method} yields an artifact but declares no P1-P7 primitive"
        assert set(cited.split("/")) <= CONFIRMATION_PRIMITIVES, f"{method}: {cited!r}"


def test_declared_primitives_are_all_in_the_closed_set() -> None:
    for method, primitives in CLASS_CONFIRMATION_PRIMITIVES.items():
        unknown = set(primitives) - CONFIRMATION_PRIMITIVES
        assert not unknown, f"{method} cites unknown primitive(s) {sorted(unknown)}"


def test_the_runbook_classes_deliberately_name_no_primitive() -> None:
    """A tier-2/3 technique has no declared result shape, so it cannot confirm a link."""
    for method in ("_test_tier2_technique", "_test_tier3_technique"):
        assert confirmation_primitives_of(method) == ""


def test_can_follow_is_ordered_by_the_enum_not_by_set_iteration() -> None:
    """Two runs must compose the same chain in the same order.

    ``can_follow`` intersects two sets, and set iteration order in Python is not
    a contract. Sorting by the enum's declaration order is what makes a chain
    plan a function of the finding SET rather than of hash seeding.
    """
    kinds = can_follow("_test_secrets_exposure", "_test_idor")
    assert kinds  # the case exists at all
    order = list(ArtifactKind)
    assert list(kinds) == sorted(kinds, key=order.index)


def test_requires_is_never_a_gate() -> None:
    """No class is GATED on an artifact — a chain adds reach, never subtracts it."""
    for method in CLASS_REQUIRES:
        # Every requiring class must also be dispatchable on its own, i.e. it is
        # in the dispatch table and does not depend on the chain layer existing.
        assert method in DISPATCHABLE_TEST_METHODS, (
            f"{method} declares a chaining requirement but is not independently "
            f"dispatchable — a chain must never be the only way a class runs"
        )
        assert requires_of(method)
