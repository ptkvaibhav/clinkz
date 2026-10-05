"""A zero write surface measured over part of the input is INDETERMINATE.

R17, and the sixth layer of invariant 14's rule. Every other coverage disclosure
in this codebase accounts for surface the engine had already READ: the plan cap
decides which endpoints get a methodology, the crawl budget which URLs become
endpoints, the probe budget which routes are asked for their verbs, method
provenance whether a verb was read at all, and the call-site split how much of
what we read we could address. None of them can see bytes that were never
fetched.

``JSCallSiteDiscoverer`` queues every same-origin chunk URL a shell references
and fetches ``_MAX_BUNDLES = 12`` of them. cal.com serves **53**. The twelve that
were read named one write, so the run reported a write surface of one route — and
nothing anywhere said that 41 chunks had gone unopened. A reader could not tell
that from an application that declares one write, and on cal.com **both were true
at once**, which is why nothing surfaced it for as long as it did.

Why this is not fixed by a re-sort or a bigger cap
---------------------------------------------------

Measured in ``docs/analysis/register.md`` R17: eight candidate ordering signals
ranked over every chunk on two targets. The queue order already reaches 93-95% of
the read-everything ceiling; the one signal that scores ~100% needs the body,
which is what the bound exists to avoid fetching; and import-graph in-degree is
actively HARMFUL at 38%, because a high in-degree chunk is a shared utility, which
is where routes are not. So the missing thing was never the coverage. It was the
sentence saying what the coverage was.
"""

from __future__ import annotations

from dataclasses import fields

import pytest

from clinkz.observability.plan_alarms import (
    BundleFetchTruncation,
    PlanAlarmRegister,
    UnreachableCallSites,
)


def _register_with(unread: int, discovered: int = 53) -> PlanAlarmRegister:
    register = PlanAlarmRegister()
    register.record_bundle_fetch(
        BundleFetchTruncation(
            budget=12,
            discovered=discovered,
            fetched=discovered - unread,
            first_omitted="https://app.test/_next/static/chunks/8231-abc.js",
            omitted_examples=[f"https://app.test/_next/static/chunks/{i}.js" for i in range(3)],
        )
    )
    register.record_unreachable_call_sites(UnreachableCallSites(seen=2, resolved=2, unresolvable=0))
    return register


def test_a_partial_read_makes_the_write_surface_indeterminate() -> None:
    """The cal.com shape: 12 of 53, and every count below is a floor."""
    summary = _register_with(unread=41).unreachable_call_site_summary()

    assert summary["write_surface_indeterminate"] is True
    assert "41 of 53" in summary["indeterminate_reason"]
    assert "12" in summary["indeterminate_reason"], "the BOUND that produced it"
    assert "chunk" in summary["indeterminate_reason"], "what CLASS of thing went unread"


def test_a_complete_read_is_a_clean_zero() -> None:
    """The verdict has to be able to come out the other way, or it says nothing."""
    summary = _register_with(unread=0, discovered=12).unreachable_call_site_summary()

    assert summary["write_surface_indeterminate"] is False
    assert summary["indeterminate_reason"] == ""
    assert summary["bundle_fetch"]["truncated"] is False


def test_the_disclosure_is_present_on_a_clean_run() -> None:
    """A section that appears only on truncation is one nobody can trust.

    Same rule as method provenance and the call-site split: "we read all of it"
    is a claim, and an absent section is not — a run that fit inside its budget
    and a run whose budget nobody measured would otherwise be identical.
    """
    summary = _register_with(unread=0, discovered=12).unreachable_call_site_summary()
    assert summary["bundle_fetch"]["measured"] is True
    assert summary["bundle_fetch"]["discovered"] == 12


def test_nothing_measured_is_not_a_clean_read() -> None:
    """A run with no bundle walk must not claim it read everything."""
    register = PlanAlarmRegister()
    register.record_unreachable_call_sites(UnreachableCallSites(seen=0, resolved=0))
    summary = register.unreachable_call_site_summary()
    assert summary["bundle_fetch"]["measured"] is False
    assert summary["write_surface_indeterminate"] is False
    assert summary["indeterminate_reason"] == ""


def test_the_unread_count_carries_its_denominator_and_examples() -> None:
    """A count with no denominator cannot be checked, only believed."""
    fetch = _register_with(unread=41).unreachable_call_site_summary()["bundle_fetch"]
    assert fetch["unread"] == 41
    assert fetch["discovered"] == 53
    assert fetch["fetched"] == 12
    assert fetch["budget"] == 12
    assert fetch["first_omitted"].endswith(".js")
    assert fetch["omitted_examples"], "the count must be checkable, not merely trusted"


# ---------------------------------------------------------------------------
# The register itself
# ---------------------------------------------------------------------------


def test_reset_clears_every_accumulator_this_register_declares() -> None:
    """The domain of ``reset`` is the register's own fields, not a written list.

    It was five hand-written ``.clear()`` calls against five fields with nothing
    asserting they matched, and every one of those accumulators retains strings
    the TARGET chose — ``first_omitted`` is a URL off the client's application,
    and ``omitted_examples`` and ``unread_examples`` are more of them. A sixth
    field added without a sixth line renders the previous engagement's URLs in
    the next engagement's client-facing coverage section, under a different
    client's id. This is that guard; it is computed, so the next field is covered
    without anybody remembering.
    """
    register = _register_with(unread=41)
    register.reset()

    for spec in fields(register):
        if spec.name == "_lock":
            continue
        assert not getattr(register, spec.name), (
            f"{spec.name} survived reset() — the previous engagement's contents, "
            f"including target-chosen URLs, carry into the next report"
        )


def test_every_accumulator_is_a_list_so_the_computed_reset_is_sound() -> None:
    """The computed reset calls ``.clear()``; a non-list field would break it.

    Asserted rather than assumed, because the fix for a hand-maintained domain is
    only as good as the assumption it replaced it with.
    """
    register = PlanAlarmRegister()
    for spec in fields(register):
        if spec.name == "_lock":
            continue
        assert isinstance(getattr(register, spec.name), list), (
            f"{spec.name} is not a list; reset() computes over fields and calls clear()"
        )


@pytest.mark.parametrize(
    ("discovered", "fetched", "expected"),
    [(53, 12, 41), (12, 12, 0), (0, 0, 0), (5, 9, 0)],
)
def test_unread_never_goes_negative(discovered: int, fetched: int, expected: int) -> None:
    """A fetched count above the discovered one is a bug, not a negative disclosure."""
    event = BundleFetchTruncation(budget=12, discovered=discovered, fetched=fetched)
    assert event.unread == expected
