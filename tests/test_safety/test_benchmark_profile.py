"""The benchmark profile — impossible to enable implicitly, and audited when it is.

The client-safe destructive refusal is the contract, not a tunable, and this
change does not loosen it. What it adds is a separate, fully explicit
declaration that ONE target is a disposable benchmark, naming the categories it
permits one by one.

Three properties are tested here and all three are structural rather than
documented:

  * **absent by default** — with no profile installed, every gate behaves byte
    for byte as it did before this module existed;
  * **impossible to enable implicitly** — there is no flag to flip and no
    partially-populated shape; the model refuses to construct without a
    verbatim attestation and an explicit category list; and
  * **audited** — every request a profile permitted is in the action log, tagged
    with the category that would otherwise have refused it.
"""

from __future__ import annotations

import pytest

from clinkz.agents._url_safety import is_destructive_form_submission, is_state_changing_url
from clinkz.models.engagement import (
    BENCHMARK_ACKNOWLEDGEMENT,
    AuthorizationRecord,
    BenchmarkProfile,
    SafetyPolicy,
    never_overridable_categories,
    overridable_categories,
)
from clinkz.safety.benchmark import (
    benchmark_override,
    get_active_benchmark_profile,
    is_benchmark_permitted,
    override_category,
    set_active_benchmark_profile,
)
from clinkz.safety.destructive import (
    CATEGORY_DELETION,
    CATEGORY_SECURITY_CONTROL,
    CATEGORY_SESSION_DESTRUCTION,
    CATEGORY_UNSAFE_METHOD,
    classify_request,
)
from clinkz.safety.governor import EngagementGovernor


def _profile(categories: list[str] | None = None) -> BenchmarkProfile:
    return BenchmarkProfile(
        target_is_throwaway=True,
        acknowledgement=BENCHMARK_ACKNOWLEDGEMENT,
        permitted_categories=categories
        or [CATEGORY_DELETION, CATEGORY_UNSAFE_METHOD, "identity_change"],
        declared_by="Pratik Vaibhav",
        declared_reference="local-lab/juice-shop-throwaway",
    )


@pytest.fixture(autouse=True)
def _no_profile_leaks() -> None:
    """The profile governs an ENGAGEMENT, not the process."""
    set_active_benchmark_profile(None)
    yield
    set_active_benchmark_profile(None)


# ---------------------------------------------------------------------------
# Impossible to enable implicitly
# ---------------------------------------------------------------------------


class TestCannotBeEnabledImplicitly:
    def test_a_false_throwaway_declaration_is_not_a_disabled_profile(self) -> None:
        """There is no 'off' shape — omitting the profile is how you disable it."""
        with pytest.raises(ValueError, match="omit the profile entirely"):
            BenchmarkProfile(
                target_is_throwaway=False,
                acknowledgement=BENCHMARK_ACKNOWLEDGEMENT,
                permitted_categories=[CATEGORY_DELETION],
                declared_by="x",
                declared_reference="y",
            )

    def test_the_attestation_must_be_reproduced_verbatim(self) -> None:
        """A boolean can be set by a copied config; this sentence cannot be typed by accident."""
        for wrong in ("yes", "I confirm this target is a disposable benchmark instance", ""):
            with pytest.raises(ValueError, match="verbatim"):
                BenchmarkProfile(
                    target_is_throwaway=True,
                    acknowledgement=wrong,
                    permitted_categories=[CATEGORY_DELETION],
                    declared_by="x",
                    declared_reference="y",
                )

    def test_there_is_no_wildcard_category(self) -> None:
        with pytest.raises(ValueError, match="at least one destructive category"):
            BenchmarkProfile(
                target_is_throwaway=True,
                acknowledgement=BENCHMARK_ACKNOWLEDGEMENT,
                permitted_categories=[],
                declared_by="x",
                declared_reference="y",
            )
        with pytest.raises(ValueError, match="unknown destructive categor"):
            BenchmarkProfile(
                target_is_throwaway=True,
                acknowledgement=BENCHMARK_ACKNOWLEDGEMENT,
                permitted_categories=["*"],
                declared_by="x",
                declared_reference="y",
            )

    @pytest.mark.parametrize("category", sorted(never_overridable_categories()))
    def test_engagement_destroying_categories_can_never_be_permitted(self, category: str) -> None:
        """The line is WHO it damages: these break the ENGAGEMENT, not the target.

        Destroying the shared session or flipping the application's security
        posture makes every later observation a measurement of a different
        application. A throwaway target does not make a corrupted engagement
        worth having.
        """
        with pytest.raises(ValueError, match="never be permitted"):
            BenchmarkProfile(
                target_is_throwaway=True,
                acknowledgement=BENCHMARK_ACKNOWLEDGEMENT,
                permitted_categories=[category],
                declared_by="x",
                declared_reference="y",
            )

    def test_a_declaring_party_and_reference_are_required(self) -> None:
        for blank in ({"declared_by": "  "}, {"declared_reference": ""}):
            kwargs = {
                "target_is_throwaway": True,
                "acknowledgement": BENCHMARK_ACKNOWLEDGEMENT,
                "permitted_categories": [CATEGORY_DELETION],
                "declared_by": "x",
                "declared_reference": "y",
                **blank,
            }
            with pytest.raises(ValueError):
                BenchmarkProfile(**kwargs)

    def test_the_authorization_record_defaults_to_no_profile(self) -> None:
        record = AuthorizationRecord(
            authorizing_party="A",
            authorizing_role="B",
            authorizing_contact="c@x.test",
            authorization_reference="SOW-1",
            permitted_techniques=["*"],
            emergency_contact="d@x.test",
        )
        assert record.benchmark_profile is None

    def test_the_safety_policy_still_carries_no_destructive_switch(self) -> None:
        """The client-safe default is untouched — this change adds, it does not loosen."""
        assert "destructive" not in " ".join(SafetyPolicy.model_fields)
        assert "benchmark" not in " ".join(SafetyPolicy.model_fields)

    def test_the_category_lists_are_disjoint_and_come_from_the_one_vocabulary(self) -> None:
        assert not (overridable_categories() & never_overridable_categories())
        # Every name is a real classifier category, not a string this model invented.
        from clinkz.safety import destructive

        known = {
            getattr(destructive, name) for name in dir(destructive) if name.startswith("CATEGORY_")
        }
        assert (overridable_categories() | never_overridable_categories()) <= known


# ---------------------------------------------------------------------------
# Absent by default
# ---------------------------------------------------------------------------


class TestAbsentByDefault:
    def test_no_profile_means_the_verdict_is_returned_untouched(self) -> None:
        verdict = classify_request("DELETE", "https://app.test/api/users/5")
        assert verdict.refused
        assert benchmark_override(verdict) is verdict
        assert override_category(verdict) == ""
        assert not is_benchmark_permitted(verdict)
        assert get_active_benchmark_profile() is None

    def test_the_navigation_gate_is_unchanged_without_a_profile(self) -> None:
        assert is_state_changing_url("https://app.test/admin/users/5/delete")
        assert is_state_changing_url("https://app.test/logout")

    def test_the_form_gate_is_unchanged_without_a_profile(self) -> None:
        form = {
            "action": "/account/delete",
            "method": "POST",
            "fields": [{"name": "confirm", "type": "submit", "value": "Delete account"}],
        }
        assert is_destructive_form_submission(form, "https://app.test/account/delete")


# ---------------------------------------------------------------------------
# What a profile actually changes
# ---------------------------------------------------------------------------


class TestWhatAProfileChanges:
    def test_a_permitted_category_becomes_an_allow_that_records_why(self) -> None:
        set_active_benchmark_profile(_profile())
        verdict = classify_request("DELETE", "https://app.test/api/users/5")
        assert verdict.refused
        overridden = benchmark_override(verdict)
        assert not overridden.refused
        # The permission is as auditable as a refusal: it names the category, the
        # declaring party, and what would otherwise have refused it.
        assert "benchmark profile" in overridden.reason
        assert verdict.category in overridden.reason
        assert "Pratik Vaibhav" in overridden.reason
        assert "Without it this would have been refused" in overridden.reason
        assert overridden.signal == verdict.signal

    def test_permission_is_by_the_category_that_decided_the_refusal_never_an_alias(self) -> None:
        """No aliasing: a profile permits exactly the categories it named.

        A bare ``DELETE`` refuses under ``unsafe_method`` (the verb is the harm),
        not under ``deletion`` (a token match). Treating one as implying the
        other would permit a category the operator did not write down, which is
        the whole thing this design refuses to do — and it would also make the
        action-log entry disagree with the profile.
        """
        set_active_benchmark_profile(_profile([CATEGORY_DELETION]))
        verdict = classify_request("DELETE", "https://app.test/api/users/5")
        assert verdict.category == CATEGORY_UNSAFE_METHOD
        assert benchmark_override(verdict).refused

        set_active_benchmark_profile(_profile([CATEGORY_UNSAFE_METHOD]))
        assert not benchmark_override(verdict).refused

    def test_a_category_the_profile_did_not_name_is_still_refused(self) -> None:
        set_active_benchmark_profile(_profile([CATEGORY_DELETION, CATEGORY_UNSAFE_METHOD]))
        verdict = classify_request(
            "POST",
            "https://app.test/account/email",
            field_names=["new_email"],
        )
        assert verdict.refused
        assert benchmark_override(verdict).refused

    def test_session_destruction_survives_a_profile_because_no_profile_can_name_it(self) -> None:
        set_active_benchmark_profile(_profile())
        assert is_state_changing_url("https://app.test/logout")
        verdict = classify_request("GET", "https://app.test/logout")
        assert verdict.category == CATEGORY_SESSION_DESTRUCTION
        assert benchmark_override(verdict).refused

    def test_a_security_posture_toggle_survives_a_profile_too(self) -> None:
        set_active_benchmark_profile(_profile())
        verdict = classify_request("GET", "https://app.test/security.php?phpids=on")
        assert verdict.category == CATEGORY_SECURITY_CONTROL
        assert benchmark_override(verdict).refused

    def test_the_navigation_gate_honours_a_permitted_category(self) -> None:
        url = "https://app.test/admin/users/5/delete"
        assert is_state_changing_url(url)
        set_active_benchmark_profile(_profile([CATEGORY_DELETION]))
        assert not is_state_changing_url(url)

    def test_the_form_gate_honours_a_permitted_category(self) -> None:
        form = {
            "action": "/account/delete",
            "method": "POST",
            "fields": [{"name": "confirm", "type": "submit", "value": "Delete account"}],
        }
        url = "https://app.test/account/delete"
        assert is_destructive_form_submission(form, url)
        set_active_benchmark_profile(_profile([CATEGORY_DELETION]))
        assert not is_destructive_form_submission(form, url)

    def test_an_allowed_request_is_never_re_permitted(self) -> None:
        set_active_benchmark_profile(_profile())
        allowed = classify_request("GET", "https://app.test/products")
        assert not allowed.refused
        assert benchmark_override(allowed) is allowed


# ---------------------------------------------------------------------------
# The action log shows exactly what it permitted
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_action_log_records_every_request_the_profile_permitted(tmp_path) -> None:
    set_active_benchmark_profile(_profile([CATEGORY_UNSAFE_METHOD]))
    governor = EngagementGovernor("bench-1", SafetyPolicy(), outputs_root=tmp_path)

    decision = await governor.authorize("DELETE", "https://app.test/api/Baskets/1", stage="exploit")
    assert decision.allowed
    governor.release()

    records = governor.action_log.read("bench-1", outputs_root=tmp_path)
    permitted = [r for r in records if r.category.startswith("benchmark_permitted:")]
    assert len(permitted) == 1
    entry = permitted[0]
    assert entry.category == f"benchmark_permitted:{CATEGORY_UNSAFE_METHOD}"
    assert entry.outcome == "sent"
    assert entry.signal == "method=DELETE"
    assert "Without it this would have been refused" in entry.reason
    assert "local-lab/juice-shop-throwaway" in entry.reason


@pytest.mark.asyncio
async def test_the_governor_stats_report_the_profile_and_its_permissions(tmp_path) -> None:
    set_active_benchmark_profile(_profile([CATEGORY_UNSAFE_METHOD]))
    governor = EngagementGovernor("bench-2", SafetyPolicy(), outputs_root=tmp_path)
    decision = await governor.authorize("DELETE", "https://app.test/api/Baskets/1")
    assert decision.allowed
    governor.release()

    stats = governor.stats()
    assert stats["benchmark_profile_active"] is True
    assert stats["benchmark_permitted_categories"] == [CATEGORY_UNSAFE_METHOD]
    assert stats["benchmark_permitted_requests"] == 1


@pytest.mark.asyncio
async def test_without_a_profile_the_governor_refuses_and_says_nothing_about_benchmarks(
    tmp_path,
) -> None:
    governor = EngagementGovernor("bench-3", SafetyPolicy(), outputs_root=tmp_path)
    decision = await governor.authorize("DELETE", "https://app.test/api/Baskets/1")
    assert not decision.allowed
    stats = governor.stats()
    assert stats["benchmark_profile_active"] is False
    assert stats["benchmark_permitted_requests"] == 0
    assert stats["benchmark_permitted_categories"] == []
    assert not [
        r
        for r in governor.action_log.read("bench-3", outputs_root=tmp_path)
        if "benchmark" in r.category
    ]


# ---------------------------------------------------------------------------
# The report header
# ---------------------------------------------------------------------------


def test_the_header_block_states_what_was_permitted_and_what_still_is_not() -> None:
    lines = _profile().header_lines()
    assert lines[0].startswith("BENCHMARK PROFILE ACTIVE")
    joined = "\n".join(lines)
    assert BENCHMARK_ACKNOWLEDGEMENT in joined
    assert "local-lab/juice-shop-throwaway" in joined
    assert CATEGORY_DELETION in joined
    # The categories that remain refused are stated too, so a reader is never
    # left to infer that "benchmark profile" meant "all rails off".
    assert CATEGORY_SESSION_DESTRUCTION in joined
    assert CATEGORY_SECURITY_CONTROL in joined


# ---------------------------------------------------------------------------
# Security-review regression: the rails must not survive a failed start
# ---------------------------------------------------------------------------


def test_the_profile_is_installed_beside_the_governor_not_before_it() -> None:
    """A rail installed outside the block that clears it is a fail-open.

    ``set_active_benchmark_profile`` first sat directly after the engagement
    gate — before the container check, the provider-chain validation and the
    ``try`` whose ``finally`` uninstalls it. A raise from either of those would
    have left the profile installed process-globally, and the NEXT engagement in
    the same process would have inherited permissive destructive rails it never
    declared. Pinned structurally rather than behaviourally: reproducing it needs
    a failed orchestrator start, and the property that matters is where the call
    sits relative to the two that guarantee its removal.
    """
    import inspect

    from clinkz.orchestrator import orchestrator as module

    source = inspect.getsource(module.OrchestratorAgent.run)
    install = source.index("set_active_benchmark_profile(self._authorization")
    uninstall = source.index("set_active_benchmark_profile(None)")
    governor_install = source.index("set_active_governor(governor)")
    finally_block = source.index("finally:")

    assert install > governor_install, (
        "the profile must be installed beside the governor, inside the try whose "
        "finally clears it — not earlier, where a raise would leave it installed"
    )
    assert install < finally_block < uninstall
