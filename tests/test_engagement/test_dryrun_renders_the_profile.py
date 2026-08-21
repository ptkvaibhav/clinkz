"""``--dry-run`` previews the profile that will actually execute.

The dry run is what a client authorises against. It is the artifact an operator
reads before agreeing that a tool may touch their application, and its whole
value is that it describes the run about to happen rather than a run in general.

It did not. ``build_dry_run_plan`` assembled ``refused_categories`` from a
module constant and never read ``scope.authorization.benchmark_profile``, so a
``--benchmark-profile`` that permits ``deletion``, ``data_reset`` and
``unsafe_method`` previewed as though all three would be refused. Consent was
obtained for a stricter engagement than the one that ran, and the difference was
exactly the set of destructive actions the operator was entitled to see.

``unsafe_method`` was worse than mis-reported: it was absent from the preview's
category list altogether, so it appeared in neither column on any run.

These tests compare the preview against
:meth:`~clinkz.models.engagement.BenchmarkProfile.permits_category` — the same
predicate :func:`~clinkz.safety.benchmark.benchmark_override` consults at
dispatch — for every category the classifier can produce.
"""

from __future__ import annotations

import pytest

from clinkz.engagement.dryrun import (
    _ALL_CATEGORIES,
    _REFUSED_CATEGORIES,
    build_dry_run_plan,
    render_dry_run,
)
from clinkz.models.engagement import (
    BENCHMARK_ACKNOWLEDGEMENT,
    AuthorizationRecord,
    BenchmarkProfile,
    overridable_categories,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.safety.benchmark import (
    benchmark_override,
    set_active_benchmark_profile,
)
from clinkz.safety.destructive import (
    CATEGORY_DATA_RESET,
    CATEGORY_DELETION,
    CATEGORY_UNSAFE_METHOD,
    DestructiveVerdict,
)

#: The DVWA ladder's profile — exactly three categories, as the stored bundles
#: record. Widening it is a control change, not a configuration tweak.
_LADDER_CATEGORIES = [CATEGORY_DATA_RESET, CATEGORY_DELETION, CATEGORY_UNSAFE_METHOD]


def _profile(categories: list[str]) -> BenchmarkProfile:
    return BenchmarkProfile(
        target_is_throwaway=True,
        acknowledgement=BENCHMARK_ACKNOWLEDGEMENT,
        permitted_categories=categories,
        declared_by="Pratik Vaibhav",
        declared_reference="local-lab/dvwa-throwaway",
    )


def _scope(profile: BenchmarkProfile | None) -> EngagementScope:
    return EngagementScope(
        name="dryrun-profile-test",
        targets=[ScopeEntry(value="localhost", type=ScopeType.DOMAIN)],
        authorization=AuthorizationRecord(
            authorizing_party="Pratik Vaibhav",
            authorizing_role="Owner",
            authorizing_contact="p@example.test",
            authorization_reference="local-lab",
            permitted_techniques=["*"],
            emergency_contact="p@example.test",
            benchmark_profile=profile,
        ),
    )


def _category_of(entry: str) -> str:
    """``"Label [category]"`` -> ``category``."""
    return entry[entry.rindex("[") + 1 : entry.rindex("]")]


@pytest.fixture(autouse=True)
def _no_ambient_profile():
    """The module-level profile is global; never leak one between tests."""
    set_active_benchmark_profile(None)
    yield
    set_active_benchmark_profile(None)


class TestPreviewAndExecutionAgree:
    """Every category, both directions, against the executing predicate."""

    @pytest.mark.parametrize("categories", [_LADDER_CATEGORIES, sorted(overridable_categories())])
    def test_every_category_lands_on_the_side_execution_puts_it(
        self, categories: list[str]
    ) -> None:
        profile = _profile(categories)
        plan = build_dry_run_plan(_scope(profile))

        previewed_refused = {_category_of(e) for e in plan.refused_categories}
        previewed_permitted = {_category_of(e) for e in plan.permitted_categories}

        # The preview accounts for every category exactly once.
        assert previewed_refused | previewed_permitted == {c for c, _ in _REFUSED_CATEGORIES}
        assert previewed_refused & previewed_permitted == set()

        # And each one is on the side the RUNTIME override would put it.
        set_active_benchmark_profile(profile)
        for category in previewed_refused | previewed_permitted:
            verdict = DestructiveVerdict(
                refused=True, category=category, reason="synthetic", signal="test"
            )
            executed_permits = not benchmark_override(verdict).refused
            previewed_permits = category in previewed_permitted
            assert previewed_permits == executed_permits, (
                f"{category!r}: preview says permitted={previewed_permits}, "
                f"execution says permitted={executed_permits}"
            )

    def test_no_profile_refuses_everything(self) -> None:
        plan = build_dry_run_plan(_scope(None))
        assert plan.permitted_categories == []
        assert len(plan.refused_categories) == len(_REFUSED_CATEGORIES)
        assert "none" in plan.benchmark_summary

    def test_the_preview_names_every_category_the_classifier_can_produce(self) -> None:
        """A category absent from the list is invisible in BOTH columns.

        ``unsafe_method`` was, and it is one of the three the DVWA ladder
        permits — so the run that most needed the disclosure was the run that
        could not have shown it.
        """
        listed = {c for c, _ in _REFUSED_CATEGORIES}
        assert listed == _ALL_CATEGORIES, (
            f"preview omits {sorted(_ALL_CATEGORIES - listed)}; "
            f"preview invents {sorted(listed - _ALL_CATEGORIES)}"
        )


class TestTheOperatorCanSeeIt:
    """A field on a model nobody renders is not a disclosure."""

    def test_permitted_categories_render_under_their_own_heading(self) -> None:
        plan = build_dry_run_plan(_scope(_profile(_LADDER_CATEGORIES)))
        text = render_dry_run(plan)

        assert "WILL BE PERMITTED" in text
        for category in _LADDER_CATEGORIES:
            assert category in text
        assert "BENCHMARK PROFILE" in text
        assert "ACTIVE" in text

    def test_a_permitted_sample_action_is_shown_as_permitted(self) -> None:
        """The demonstrated verdicts follow the profile too, not just the list.

        The sample is keyed on ``unsafe_method`` rather than ``deletion``
        because that is the category the classifier actually DECIDED
        ``DELETE /api/records/1`` on — permission is by the deciding category,
        never by an alias that happens to describe the same action. Profiling
        ``deletion`` alone leaves this request refused, and the preview has to
        say so or it over-reports what was authorised.
        """
        permissive = build_dry_run_plan(_scope(_profile([CATEGORY_UNSAFE_METHOD])))
        deletes = [e for e in permissive.destructive_examples if e.split()[-2] == "DELETE"]
        assert deletes, "no DELETE sample in the demonstration set"
        assert all(e.startswith("PERMITTED") for e in deletes), deletes

        # And the alias does NOT permit it, in the preview exactly as at dispatch.
        aliased = build_dry_run_plan(_scope(_profile([CATEGORY_DELETION])))
        still_refused = [e for e in aliased.destructive_examples if e.split()[-2] == "DELETE"]
        assert all(e.startswith("REFUSE") for e in still_refused), still_refused

    def test_a_profile_run_carries_a_warning(self) -> None:
        plan = build_dry_run_plan(_scope(_profile(_LADDER_CATEGORIES)))
        assert any("BENCHMARK PROFILE" in w for w in plan.warnings)

    def test_never_overridable_categories_stay_refused_under_any_profile(self) -> None:
        """Session destruction and posture toggles damage the ENGAGEMENT.

        They cannot be put in a profile at all, so the preview must keep showing
        them as refused however permissive the profile is.
        """
        plan = build_dry_run_plan(_scope(_profile(sorted(overridable_categories()))))
        refused = {_category_of(e) for e in plan.refused_categories}
        assert "session_destruction" in refused
        assert "security_control_toggle" in refused
