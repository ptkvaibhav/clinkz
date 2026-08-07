"""The verdict is a function of engine-owned observations, and nothing else.

The rule these defend is the one ``_evidence_strength`` was narrowed for: a
guard that reads text the target controls hands the target a suppression — or an
authorisation — primitive. A browser oracle renders target-authored everything,
so the defence has to be structural.
"""

from __future__ import annotations

from clinkz.browser.witness import ExecutionWitness, WitnessRefusal, WitnessVerdict

NONCE = "aaaaaaaaaaaaaaaa"
CONTROL = "bbbbbbbbbbbbbbbb"


def _verdict(**kw) -> WitnessVerdict:
    base = {"nonce": NONCE, "control_nonce": CONTROL, "binding_name": "__clinkz_w_1"}
    base.update(kw)
    return WitnessVerdict(**base)


class TestExecutionRequiresTheNonce:
    def test_nonce_returned_confirms(self) -> None:
        v = _verdict(witnesses=[ExecutionWitness(value=NONCE)])
        v.decide()
        assert v.executed is True
        assert v.refusal is WitnessRefusal.NONE

    def test_no_call_at_all_is_a_clean_negative(self) -> None:
        v = _verdict()
        v.decide()
        assert v.executed is False
        assert v.refusal is WitnessRefusal.NOT_EXECUTED
        assert v.is_target_statement is True

    def test_a_call_without_our_nonce_never_confirms(self) -> None:
        """Observed live: a page's own JSONP call reached the binding carrying the
        endpoint's data. The binding firing is not the oracle — the nonce is."""
        v = _verdict(witnesses=[ExecutionWitness(value='{"answer":"15"}')])
        v.decide()
        assert v.executed is False
        assert v.refusal is WitnessRefusal.NOT_EXECUTED

    def test_a_substring_of_the_nonce_does_not_confirm(self) -> None:
        v = _verdict(witnesses=[ExecutionWitness(value=NONCE[:-1])])
        v.decide()
        assert v.executed is False

    def test_the_nonce_embedded_in_other_text_does_not_confirm(self) -> None:
        """Equality, never containment: a page echoing the nonce inside a larger
        string has not called us with it."""
        v = _verdict(witnesses=[ExecutionWitness(value=f"prefix{NONCE}suffix")])
        v.decide()
        assert v.executed is False

    def test_empty_nonce_can_never_confirm(self) -> None:
        v = _verdict(nonce="", witnesses=[ExecutionWitness(value="")])
        v.decide()
        assert v.executed is False


class TestNeverExecutedControlIsMandatory:
    def test_control_firing_invalidates_the_run_even_with_a_positive(self) -> None:
        """If the channel can report a nonce that was never sent, it can report
        one that was — so a positive alongside a live control is inadmissible."""
        v = _verdict(
            witnesses=[ExecutionWitness(value=NONCE), ExecutionWitness(value=CONTROL)],
        )
        v.decide()
        assert v.executed is False
        assert v.refusal is WitnessRefusal.CONTROL_NONCE_OBSERVED
        assert v.control_silent is False
        assert v.is_target_statement is False

    def test_control_silence_is_recorded_on_every_confirm(self) -> None:
        v = _verdict(witnesses=[ExecutionWitness(value=NONCE)])
        v.decide()
        assert v.control_silent is True
        assert CONTROL in v.evidence_summary()


class TestCSPBypassCannotProduceAConfirmation:
    def test_a_browser_ignoring_csp_confirms_nothing(self) -> None:
        v = _verdict(witnesses=[ExecutionWitness(value=NONCE)], bypass_csp_disabled=False)
        v.decide()
        assert v.executed is False
        assert v.refusal is WitnessRefusal.SAFETY_REFUSED


class TestPageAuthoredTextNeverDecides:
    def test_console_violations_do_not_suppress_a_witnessed_execution(self) -> None:
        """A page can print 'Refused to execute'. It cannot un-run our script."""
        v = _verdict(
            witnesses=[ExecutionWitness(value=NONCE)],
            console_violations=["Refused to execute inline script because it violates CSP"],
            policy_in_force="script-src 'none'",
        )
        v.decide()
        assert v.executed is True

    def test_policy_text_does_not_manufacture_a_confirmation(self) -> None:
        v = _verdict(policy_in_force="script-src 'unsafe-inline'", console_violations=[])
        v.decide()
        assert v.executed is False

    def test_final_url_is_evidence_not_a_verdict_input(self) -> None:
        v = _verdict(final_url="http://target/?executed=true")
        v.decide()
        assert v.executed is False


class TestOracleFailuresAreNotStatementsAboutTheTarget:
    def test_every_oracle_failure_is_excluded_from_target_statements(self) -> None:
        for refusal in (
            WitnessRefusal.ORACLE_UNAVAILABLE,
            WitnessRefusal.OUT_OF_SCOPE,
            WitnessRefusal.STATE_CHANGING_URL,
            WitnessRefusal.SAFETY_REFUSED,
            WitnessRefusal.NAVIGATION_FAILED,
            WitnessRefusal.CONTROL_NONCE_OBSERVED,
        ):
            v = _verdict(refusal=refusal)
            assert v.is_target_statement is False, refusal

    def test_only_execution_and_clean_non_execution_speak_about_the_target(self) -> None:
        assert _verdict(executed=True).is_target_statement is True
        assert _verdict(refusal=WitnessRefusal.NOT_EXECUTED).is_target_statement is True


class TestEvidenceIsRawAuditable:
    def test_summary_carries_both_halves_and_the_control(self) -> None:
        v = _verdict(
            witnesses=[ExecutionWitness(value=NONCE)],
            policy_in_force="script-src 'self'",
            policy_source="header",
            template_id="inline_script",
        )
        v.decide()
        summary = v.evidence_summary()
        assert f"nonce_injected='{NONCE}'" in summary
        assert f"nonce_returned='{NONCE}'" in summary
        assert "control_silent=True" in summary
        assert "bypass_csp_disabled=True" in summary
        assert "script-src 'self'" in summary
