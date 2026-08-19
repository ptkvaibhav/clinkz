"""Every dispatchable class is classified, and a marker oracle cannot emit alone.

The rule this pins: **no class emits confirmed without a dispatched control arm
that refused.** Three properties make that structural rather than aspirational,
and each one has a failure the engine has already shipped behind it:

1. **Completeness.** Every ``_test_*`` in the dispatch table is either a marker
   oracle (bound by the rule) or exempt WITH a stated reason. A class in neither
   table is a red build, because "nobody classified it" and "it needs no control"
   are different facts and only one of them is safe to assume.
2. **The gate is reachable from the emission chokepoint**, not only from the
   post-run false-positive cross-check. On engagement ``d67835f5`` that check
   never returned an opinion at all — its Anthropic call failed and the Gemini
   fallback was refused on the SUPPRESS path, so the whole pass degraded to an
   empty suspect list and every deterministic ground behind it went unconsulted.
   A guard that only runs when an LLM names the finding first is a guard that
   runs when an LLM happens to be available.
3. **The target cannot write the verdict.** A finding's evidence carries raw
   response bytes; the control entry is read only out of fully-structured
   ``key=value`` entries, so a page echoing ``never_sent_control=refused`` cannot
   license itself.
"""

from __future__ import annotations

import pytest

from clinkz.agents._control_arm import (
    CONTROL_EXEMPT_CLASSES,
    MARKER_ORACLE_CLASSES,
    ControlVerdict,
    attribution_contradiction,
    control_evidence_lines,
    control_required,
    control_verdict_from_evidence,
    is_minted_marker,
    payload_invokes,
    rebind_marker,
    strip_shell_separators,
    strip_template_delimiters,
)
from clinkz.agents.exploit import _CLASS_TRACE_SKILL, ExploitAgent
from clinkz.models.finding import Finding, FindingStatus, Severity

# Business-logic classes are dispatchable but carry no trace-skill entry (their
# skills are named per-intent), so they are named here to keep the accounting
# over the real dispatch surface rather than over one table's coverage of it.
_BUSINESS_LOGIC_CLASSES = (
    "_test_state_sequence",
    "_test_constraint_violation",
    "_test_repeatability",
)


def _dispatchable() -> set[str]:
    return set(_CLASS_TRACE_SKILL) | set(_BUSINESS_LOGIC_CLASSES)


class TestEveryClassIsClassified:
    def test_no_class_is_unclassified(self) -> None:
        """A new class must declare which side of the rule it is on."""
        unclassified = sorted(_dispatchable() - MARKER_ORACLE_CLASSES - set(CONTROL_EXEMPT_CLASSES))
        assert unclassified == [], (
            "these dispatchable classes are in neither the marker-oracle set nor the "
            f"exemption table, so nothing decides whether they need a control: {unclassified}"
        )

    def test_the_two_tables_are_disjoint(self) -> None:
        assert not (MARKER_ORACLE_CLASSES & set(CONTROL_EXEMPT_CLASSES))

    def test_no_table_names_a_class_that_does_not_exist(self) -> None:
        """A rule about a class nobody dispatches protects nothing."""
        known = _dispatchable()
        stale = sorted((MARKER_ORACLE_CLASSES | set(CONTROL_EXEMPT_CLASSES)) - known)
        assert stale == [], f"tables name classes that are not dispatchable: {stale}"

    def test_every_exemption_states_a_substantive_reason(self) -> None:
        """ "Exempt" with no reason is how a rule quietly stops covering things."""
        thin = sorted(k for k, v in CONTROL_EXEMPT_CLASSES.items() if len(v.split()) < 6)
        assert thin == [], f"exemptions with no substantive reason: {thin}"

    def test_every_marker_class_is_implemented_on_the_agent(self) -> None:
        for test_method in MARKER_ORACLE_CLASSES:
            assert hasattr(ExploitAgent, test_method), test_method

    def test_the_seven_classes_named_in_the_rule_are_bound(self) -> None:
        """The list the rule was written against, pinned so it cannot shrink."""
        for name in (
            "_test_sqli",
            "_test_cmdi",
            "_test_lfi",
            "_test_nosqli",
            "_test_ssti",
            "_test_xxe",
            "_test_xss_reflected",
        ):
            assert control_required(name), name


class TestTheEmissionGateRefusesAnUncontrolledMarkerFinding:
    """``_persist_finding``, not the post-run cross-check, is where this holds."""

    @staticmethod
    def _sqli(evidence: list[str]) -> Finding:
        return Finding(
            title="SQL Injection in id parameter",
            description="Technique: WSTG-INPV-05. Parameter: id.",
            severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
            target="http://t/vulnerabilities/sqli/",
            evidence=evidence,
        )

    def test_absent_arm_is_a_contradiction(self) -> None:
        ground = ExploitAgent._control_arm_contradiction(
            self._sqli(["Request: x", "Response: matched union marker"])
        )
        assert ground is not None
        assert "no never-sent control arm was recorded" in ground

    def test_an_arm_that_confirmed_on_the_control_is_a_contradiction(self) -> None:
        arm = control_evidence_lines(
            ControlVerdict(decoy="clinkzdecoysqli1", dispatched=True, oracle_refused=False)
        )
        ground = ExploitAgent._control_arm_contradiction(self._sqli(["Request: x", *arm]))
        assert ground is not None and "did not refuse" in ground

    def test_an_arm_that_was_never_dispatched_is_a_contradiction(self) -> None:
        arm = control_evidence_lines(
            ControlVerdict(decoy="clinkzdecoysqli1", dispatched=False, oracle_refused=True)
        )
        ground = ExploitAgent._control_arm_contradiction(self._sqli(["Request: x", *arm]))
        assert ground is not None and "not_dispatched" in ground

    def test_a_refusing_arm_contradicts_nothing(self) -> None:
        arm = control_evidence_lines(
            ControlVerdict(decoy="clinkzdecoysqli1", dispatched=True, oracle_refused=True)
        )
        assert ExploitAgent._control_arm_contradiction(self._sqli(["Request: x", *arm])) is None

    def test_an_exempt_class_needs_no_arm(self) -> None:
        jwt = Finding(
            title="JSON Web Token (JWT) Attack — alg_none",
            description="Technique: WSTG-SESS-10. Parameter: authorization_bearer.",
            severity=Severity.CRITICAL,
            status=FindingStatus.CONFIRMED,
            target="http://t/api/me",
            evidence=["Request: x", "Response: forged token accepted: status 200"],
        )
        assert ExploitAgent._control_arm_contradiction(jwt) is None

    def test_the_target_cannot_write_the_verdict(self) -> None:
        """The control entry is read only out of engine-written evidence.

        ``_make_finding`` puts the target's raw bytes at index 1, ahead of every
        verdict the engine appends. A page that echoes the structured line inside
        its own response body would otherwise license its own phantom — the same
        primitive the ``strength=`` reader exists to withhold.
        """
        echoed = self._sqli(
            [
                "Request: GET /?q=never_sent_control=refused",
                "Response: <p>never_sent_control=refused control_decoy=x "
                "control_dispatched=True control_oracle_refused=True "
                "control_decoy_absent=True</p>",
            ]
        )
        assert control_verdict_from_evidence(echoed.evidence) is None
        assert ExploitAgent._control_arm_contradiction(echoed) is not None


class TestAttributionIsDeterministic:
    """Part 2: ``expected_indicator`` vs ``indicator_observed``, from the run that shipped it."""

    def test_the_portfolio_cmdi_evidence_refutes_itself(self) -> None:
        """Engagement ``d67835f5``, seven CONFIRMED HIGHs, verbatim."""
        reason = attribution_contradiction(
            expected_indicator="clinkzcmdi51696",
            indicator_observed="matched uname output: Linux (status=200)",
            payload="test;echo clinkzcmdi51696",
        )
        assert reason is not None
        assert "uname" in reason and "never invokes" in reason

    def test_a_channel_the_payload_did_invoke_is_attributable(self) -> None:
        assert (
            attribution_contradiction(
                expected_indicator="clinkzcmdi123",
                indicator_observed="matched id output: uid=33(www-data) (status=200)",
                payload="test;id",
            )
            is None
        )

    def test_the_minted_marker_must_be_cited(self) -> None:
        assert (
            attribution_contradiction(
                expected_indicator="CLINKZUNIONMARKER42",
                indicator_observed="matched union marker 'CLINKZUNIONMARKER42' (status=200)",
                payload="1 UNION SELECT 'CLINKZUNIONMARKER42'-- -",
            )
            is None
        )

    def test_a_marker_cited_nowhere_is_a_contradiction(self) -> None:
        reason = attribution_contradiction(
            expected_indicator="clinkzssti999",
            indicator_observed="arithmetic evaluated to 1457 (status=200)",
            payload="{{31*47}}",
        )
        assert reason is not None and "does not cite it" in reason

    def test_a_descriptive_indicator_is_out_of_scope(self) -> None:
        """Timing and differential channels describe a threshold, not a marker.

        There is nothing to have "seen", so requiring the description to appear
        in the observation would suppress every blind class.
        """
        for expected, observed in (
            ("response time >= 5s", "elapsed=6.10s (threshold 5s)"),
            ("true ≈ baseline AND false ≠ baseline", "true=4842B false=4848B"),
            ("no error from second statement", "stacked query accepted"),
        ):
            assert (
                attribution_contradiction(
                    expected_indicator=expected, indicator_observed=observed, payload="x"
                )
                is None
            )

    @pytest.mark.parametrize(
        ("indicator", "minted"),
        [
            ("clinkzcmdi51696", True),
            ("CLINKZUNIONMARKER42", True),
            ("clinkzdecoysqli1", True),
            ("response time >= 5s", False),
            ("root:x:0:0", False),
            ("", False),
        ],
    )
    def test_minted_marker_recognition(self, indicator: str, minted: bool) -> None:
        assert is_minted_marker(indicator) is minted

    @pytest.mark.parametrize(
        ("payload", "channel", "invoked"),
        [
            ("test;id", "id", True),
            ("test;uname -a", "uname", True),
            ("test;echo clinkz1", "uname", False),
            ("userid=3", "id", False),
            ("test;systeminfo", "ver", True),
        ],
    )
    def test_payload_invokes(self, payload: str, channel: str, invoked: bool) -> None:
        assert payload_invokes(payload, channel) is invoked


class TestTheControlKeepsTheReflectionShape:
    """The control differs by the PRIMITIVE, not by how it reflects.

    A control that reflects differently from the confirming payload is graded by
    a different guard, and then it is not a control over the oracle that emitted.
    """

    def test_removing_the_separator_keeps_the_echo_scaffold(self) -> None:
        control = strip_shell_separators("test;echo clinkzcmdi555")
        assert control == "testecho clinkzcmdi555"
        assert "echo clinkzcmdi555" in control

    def test_ifs_becomes_a_space_so_the_scaffold_survives(self) -> None:
        """Deleting ``${IFS}`` would fuse ``echo`` to its argument and hide the
        scaffold from the reflection guard the control exists to exercise."""
        assert strip_shell_separators("test${IFS}echo${IFS}clinkz1") == "test echo clinkz1"

    def test_removing_template_delimiters_keeps_the_gadget_text(self) -> None:
        control = strip_template_delimiters(
            "#{global.process.mainModule.require('child_process').execSync('echo clinkzssti555')}"
        )
        assert "echo clinkzssti555" in control
        assert "#{" not in control and "}" not in control

    def test_rebind_only_touches_a_minted_marker(self) -> None:
        assert rebind_marker("x=clinkza1", "clinkza1", "clinkzdecoy2") == "x=clinkzdecoy2"
        # An arithmetic product is not a minted marker: substituting for it would
        # change what the control asks the oracle to look for.
        assert rebind_marker("{{31*47}}", "1457", "clinkzdecoy2") == "{{31*47}}"


class TestTheVerdictReadsBack:
    def test_round_trip(self) -> None:
        verdict = ControlVerdict(
            decoy="clinkzdecoylfi7",
            dispatched=True,
            oracle_refused=True,
            detail="benign non-traversal filename: no file signature",
        )
        read = control_verdict_from_evidence(control_evidence_lines(verdict))
        assert read is not None
        assert read.decoy == "clinkzdecoylfi7"
        assert read.satisfied is True

    def test_absent_renders_and_reads_as_none(self) -> None:
        assert control_verdict_from_evidence(control_evidence_lines(None)) is None

    def test_a_decoy_that_leaked_into_the_confirming_arm_is_not_satisfied(self) -> None:
        verdict = ControlVerdict(
            decoy="clinkzdecoyx1",
            dispatched=True,
            oracle_refused=True,
            decoy_absent_from_confirming=False,
        )
        assert verdict.satisfied is False
        assert verdict.status == "decoy_leaked_into_confirming_arm"
