"""A run where nothing answered is not a clean run.

``DegradationRegister.degraded`` was ``bool(self._events)``, and an event was
written only when a provider **substituted** for another. A chain that runs out
substitutes nothing, so the worst possible outcome — nobody answered at all —
wrote nothing at all, and the eligibility flag computed from that list said the
run was fit to be a baseline.

Two recorded instances, both in ``tests/fixtures/run3_all_providers_exhausted.json``
and both taken verbatim from the artifacts the runs actually shipped:

* **Engagement 2e21a200.** Recon, scan AND exploit each raised ``All providers
  exhausted``. Zero findings. ``model_stamp`` recorded ``provider: "exhausted"``
  for all three stages; ``provider_degradation`` recorded
  ``provider_degraded: false, baseline_eligible: true``. The document contained
  both halves of a contradiction and rendered the reassuring one.

* **Engagement 9317e813.** One methodology call died with
  ``stop_reason=refusal`` behind the same ``All providers exhausted``, and the
  register recorded nothing. Its trace names ``anthropic`` rather than
  ``exhausted`` — ``_last_used_provider`` was already set by an earlier
  successful call on the same client — so this instance is INVISIBLE to the
  model stamp. That is why there are two witnesses and not one.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from clinkz.llm.degradation import (
    EXHAUSTED_PROVIDER,
    DegradationKind,
    DegradationRegister,
    ProviderAbsence,
    ProviderFallback,
    exhausted_stages,
    reconcile_with_model_stamp,
)

_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "run3_all_providers_exhausted.json"


@pytest.fixture(scope="module")
def run3() -> dict[str, Any]:
    """The third variance-envelope run's own artifacts."""
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def _absence(**overrides: Any) -> ProviderAbsence:
    base: dict[str, Any] = {
        "agent_role": "recon",
        "method": "reason",
        "kind": DegradationKind.CHAIN_EXHAUSTED,
        "chain": ("anthropic", "openai"),
        "reason": "RateLimitError",
    }
    base.update(overrides)
    return ProviderAbsence(**base)


class TestAnAbsenceDegradesTheRun:
    """Substitution is one of three ways routing fails, and was the only one counted."""

    def test_an_exhausted_chain_degrades(self) -> None:
        register = DegradationRegister()
        assert register.degraded is False
        register.record_absence(_absence())
        assert register.degraded is True
        assert register.baseline_eligible is False

    def test_a_terminal_exclusion_degrades(self) -> None:
        register = DegradationRegister()
        register.record_absence(
            _absence(kind=DegradationKind.TERMINAL_EXCLUSION, provider="gemini")
        )
        assert register.degraded is True
        assert register.baseline_eligible is False

    def test_baseline_eligibility_follows_degraded_rather_than_the_event_list(self) -> None:
        """The pair drifted because they were two expressions of one fact.

        ``baseline_eligible`` was ``not self.degraded`` and ``degraded`` was
        ``bool(self._events)``, so adding a second kind of event to one of them
        would have left the other behind. It reads the property now.
        """
        register = DegradationRegister()
        register.record_absence(_absence())
        assert register.baseline_eligible is not register.degraded

    def test_the_summary_names_absences_apart_from_substitutions(self) -> None:
        register = DegradationRegister()
        register.record(
            ProviderFallback(
                agent_role="exploit",
                method="reason",
                asked_provider="anthropic",
                asked_model="claude-sonnet-5",
                served_provider="gemini",
                served_model="gemini-3.7-flash",
                reason="RateLimitError",
                decision_bearing=True,
            )
        )
        register.record_absence(_absence(agent_role="scan"))
        summary = register.summary()
        assert summary["provider_degraded"] is True
        assert summary["fallback_count"] == 1
        assert summary["absence_count"] == 1
        assert summary["absence_kinds"] == {"chain_exhausted": 1}
        assert sorted(summary["call_sites"]) == ["exploit.reason", "scan.reason"]
        assert summary["absences"][0]["kind"] == "chain_exhausted"
        assert summary["absences"][0]["provider"] == "", (
            "an exhausted chain has no served provider - inventing one is what made it "
            "inexpressible as a fallback and therefore unrecorded"
        )

    def test_a_clean_register_still_makes_the_claim(self) -> None:
        """Present on a clean run: a section that appears only on failure is invisible."""
        summary = DegradationRegister().summary()
        assert summary["provider_degraded"] is False
        assert summary["baseline_eligible"] is True
        assert summary["absence_count"] == 0
        assert summary["absences"] == []

    def test_reset_clears_absences_too(self) -> None:
        register = DegradationRegister()
        register.record_absence(_absence())
        register.reset()
        assert register.degraded is False


class TestTheModelStampIsTheSecondWitness:
    """The register misses what the stamp catches, and vice versa."""

    def test_exhausted_stages_reads_the_stamp(self, run3: dict[str, Any]) -> None:
        assert exhausted_stages(run3["model_stamp"]) == ["exploit", "recon", "scan"]

    def test_a_healthy_stamp_names_nothing(self, run3: dict[str, Any]) -> None:
        assert exhausted_stages(run3["run1_smaller_instance"]["model_stamp"]) == []

    def test_the_stamp_flips_run_3s_shipped_verdict(self, run3: dict[str, Any]) -> None:
        """The exact pair that shipped, reconciled."""
        shipped = run3["provider_degradation_as_shipped"]
        assert shipped["provider_degraded"] is False, "the fixture must be the defect itself"
        assert shipped["baseline_eligible"] is True

        reconciled = reconcile_with_model_stamp(shipped, run3["model_stamp"])
        assert reconciled["provider_degraded"] is True
        assert reconciled["baseline_eligible"] is False
        assert reconciled["exhausted_stages"] == ["exploit", "recon", "scan"]
        assert reconciled["absence_source"] == "model_stamp", (
            "a degraded verdict beside absence_count=0 reads as a rendering bug; the "
            "reconciliation says which witness produced it"
        )

    def test_reconciliation_does_not_mutate_its_input(self, run3: dict[str, Any]) -> None:
        shipped = dict(run3["provider_degradation_as_shipped"])
        before = json.dumps(shipped, sort_keys=True)
        reconcile_with_model_stamp(shipped, run3["model_stamp"])
        assert json.dumps(shipped, sort_keys=True) == before

    def test_reconciliation_only_ever_tightens(self) -> None:
        """A clean stamp is not evidence against a recorded degradation.

        The register's positive findings are observations. An empty stamp means
        the trace saw no exhausted stage, which is exactly the run-1 shape - and
        clearing a real fallback on that basis would delete the record of a
        degradation whose output is already inside the findings.
        """
        register = DegradationRegister()
        register.record(
            ProviderFallback(
                agent_role="exploit",
                method="reason",
                asked_provider="anthropic",
                asked_model="claude-sonnet-5",
                served_provider="gemini",
                served_model="gemini-3.7-flash",
            )
        )
        healthy = [
            {"stage": "exploit", "provider": "anthropic", "model": "claude-sonnet-5", "calls": 9}
        ]
        reconciled = reconcile_with_model_stamp(register.summary(), healthy)
        assert reconciled["provider_degraded"] is True
        assert reconciled["baseline_eligible"] is False

    def test_run_1s_instance_is_invisible_to_the_stamp(self, run3: dict[str, Any]) -> None:
        """Which is the whole argument for keeping both witnesses.

        The failing call raised ``LLMUnavailableError`` from the chain-exhaustion
        path, so the register catches it live. The trace recorded ``anthropic``
        because an earlier call on the same client had already set
        ``_last_used_provider``, so the stamp cannot.
        """
        run1 = run3["run1_smaller_instance"]
        assert run1["llm_call_errors"], "the fixture must carry the failing call"
        assert run1["llm_call_errors"][0]["error_class"] == "LLMUnavailableError"
        assert run1["llm_call_errors"][0]["stop_reason"] == "refusal"
        assert run1["llm_call_errors"][0]["provider_in_trace"] != EXHAUSTED_PROVIDER
        assert (
            reconcile_with_model_stamp(
                run1["provider_degradation_as_shipped"], run1["model_stamp"]
            )["provider_degraded"]
            is False
        ), (
            "the stamp alone cannot see this one - only the register recording the "
            "chain-exhaustion raise catches it"
        )


class TestTheDispatcherRecordsBothAbsences:
    """The two raise sites, asserted against the source that must reach them."""

    @staticmethod
    def _source() -> str:
        import clinkz.llm.fallback as fallback

        return Path(fallback.__file__).read_text(encoding="utf-8")

    def test_the_chain_exhaustion_raise_records_first(self) -> None:
        source = self._source()
        raise_index = source.index("All providers exhausted for profile")
        record_index = source.rindex("DegradationKind.CHAIN_EXHAUSTED", 0, raise_index)
        assert record_index < raise_index, (
            "the absence must be recorded BEFORE the raise - an exception leaving the "
            "dispatcher unrecorded is the original defect"
        )

    def test_the_terminal_exclusion_is_recorded(self) -> None:
        source = self._source()
        assert "DegradationKind.TERMINAL_EXCLUSION" in source
        marker = source.index("_ACCOUNT_DISABLED_PROVIDERS.add(provider)")
        following = source[marker : marker + 1600]
        assert "DegradationKind.TERMINAL_EXCLUSION" in following, (
            "every later call in the run uses a shorter chain than the configured one "
            "and is silent about it, so the disqualification is recorded where the fact "
            "is known"
        )
