"""A control arm's outcome is the PROOF, and two consumers read it as the phantom.

An oracle that carries its own control renders the refusing arms beside the
confirming one, in one string. The juice-shop authentication bypass ships all
three at once::

    probe(tautology): status=200 body_token ...
      | control(contradiction): status=401 no auth artifact
      | benign: status=401 no auth artifact

Those two 401s are what make the 200 mean anything. Both of the defects pinned
here are the same mistake — reading an arm's outcome without knowing which arm
produced it — and both landed on that same finding:

1. **The re-grade detector** called it ``NO_ARM``. It asks whether a class is
   marker-bound, which is declared per ``_test_*``; but ``_test_sqli`` confirms
   on five channels and ``auth_bypass`` is a three-arm differential whose
   contradiction and benign arms are DISPATCHED and must refuse. Neither the
   class name nor the indicator name carries that fact — ``_test_nosqli`` has an
   ``auth_bypass`` channel with no shape-matched contradiction at all — so the
   producer declares it and the consumer reads the declaration.
2. **The error-page ground** would have demoted it, once moved to the
   unconditional emission chokepoint. It scans evidence for ``status=4xx``, and
   the only reason it did not fire is that ``re.search`` stopped at the
   tautology's ``200`` before reaching either ``401``. That is an ordering, not
   a rule.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from clinkz.agents._control_arm import (
    confirming_statuses,
    indicator_is_self_controlled,
    structured_evidence_field,
)
from clinkz.models.finding import Finding, FindingStatus, Severity
from clinkz.models.methodology import InjectionType, NoSQLInjectionType
from clinkz.models.vuln_classes import VULN_CLASSES, ControlArm

#: The juice-shop authentication bypass's observation, as stored on disk.
D8_OBSERVATION = (
    "authenticated as a principal whose credential was never supplied: "
    "admin@juice-sh.op :: probe(tautology): status=200 body_token at response body "
    "(JWT) principal=admin@juice-sh.op | control(contradiction): status=401 no auth "
    "artifact | benign: status=401 no auth artifact :: carrier assertion PASSED"
)

#: A confirmed attack chain's observation. Its decoy control REFUSED, which is
#: the whole point of dispatching it.
CHAIN_OBSERVATION = (
    "real_status=200 accepted=True | decoy_status=403 accepted=False | "
    "acceptance_signal=identity_echo | composed_grade=confirmed"
)


def _auth_bypass_finding(*, evidence: list[str]) -> Finding:
    return Finding(
        title="Authentication bypass via SQL injection in email",
        description="Technique: WSTG-INPV-05. Parameter: email.",
        severity=Severity.CRITICAL,
        status=FindingStatus.CONFIRMED,
        target="http://t/rest/user/login",
        evidence=evidence,
    )


class TestWhichArmProducedThatStatus:
    def test_only_the_confirming_arm_is_read(self) -> None:
        assert confirming_statuses(D8_OBSERVATION) == [200]

    def test_a_named_arm_field_is_not_the_captured_response(self) -> None:
        """``decoy_status=403`` is a fact ABOUT the decoy, not a failed request.

        Read naively it demotes every confirmed attack chain whose decoy control
        did exactly what it was dispatched to do. A chain records per-arm fields
        and no captured-response status at all, so the honest answer is that
        this evidence says nothing about a captured response — and a ground that
        has nothing to read must not fire.
        """
        assert confirming_statuses(CHAIN_OBSERVATION) == []
        assert 403 not in confirming_statuses(CHAIN_OBSERVATION)

    def test_a_confirmed_chain_is_not_demoted_by_its_own_control(self) -> None:
        from clinkz.agents.exploit import ExploitAgent

        agent = object.__new__(ExploitAgent)
        chain = Finding(
            title="Confirmed attack chain — session token -> account takeover",
            description="Technique: chaining. Parameter: session_token.",
            severity=Severity.CRITICAL,
            status=FindingStatus.CONFIRMED,
            target="http://t/rest/user/whoami",
            evidence=["Request: Chain: a -> b", f"Response: {CHAIN_OBSERVATION}"],
        )
        assert agent._fp_ground_error_page(chain) is None

    def test_unlabelled_prose_is_still_the_captured_response(self) -> None:
        """The reflection-in-an-error-page phantom must stay catchable."""
        assert confirming_statuses("matched 'clinkzX' (status=500)") == [500]
        assert confirming_statuses("reflected marker (status=404)") == [404]

    def test_ordering_was_never_the_rule(self) -> None:
        """Reverse the arms and a first-match reader flips on identical facts."""
        reversed_arms = (
            "control(contradiction): status=401 no auth artifact "
            "| probe(tautology): status=200 body_token"
        )
        assert confirming_statuses(reversed_arms) == [200]

    def test_the_error_page_ground_clears_the_real_finding(self) -> None:
        from clinkz.agents.exploit import ExploitAgent

        agent = object.__new__(ExploitAgent)
        finding = _auth_bypass_finding(
            evidence=[
                "Request: login request to http://t/rest/user/login",
                f"Response: {D8_OBSERVATION}",
                "indicator_type=auth_bypass",
            ]
        )
        assert agent._fp_ground_error_page(finding) is None


class TestTheProducerDeclaresItsOwnChannels:
    def test_sqli_auth_bypass_is_declared_self_controlled(self) -> None:
        reason = indicator_is_self_controlled("_test_sqli", "auth_bypass")
        assert reason and "three-arm" in reason

    def test_the_same_indicator_name_on_another_class_is_not(self) -> None:
        """``_test_nosqli``'s ``auth_bypass`` compares against a benign baseline.

        No shape-matched contradiction, so it relies on the never-sent control
        like every other marker channel. A consumer keying on the indicator NAME
        gets this one wrong; one keying on the class name gets the SQLi one
        wrong. Only the declaration is right about both.
        """
        assert indicator_is_self_controlled("_test_nosqli", "auth_bypass") is None

    def test_the_other_sqli_channels_are_still_bound(self) -> None:
        for channel in ("union_data", "error_string", "time_delta", "content_diff"):
            assert indicator_is_self_controlled("_test_sqli", channel) is None

    def test_every_declared_channel_is_a_real_indicator(self) -> None:
        """Verified against the producer's own enums, so it cannot become a wish."""
        known = {t.value for t in InjectionType} | {t.value for t in NoSQLInjectionType}
        for vuln_class in VULN_CLASSES:
            for indicator in vuln_class.control_arm.self_controlled_indicators:
                assert indicator in known, (
                    f"{vuln_class.test_method} declares {indicator!r} self-controlled, "
                    "but no methodology emits that indicator type"
                )

    def test_an_exemption_must_state_a_reason(self) -> None:
        with pytest.raises(ValidationError):
            ControlArm(self_controlled_indicators=("auth_bypass",))

    def test_the_live_gate_does_not_relax(self) -> None:
        """The engine CAN dispatch a never-sent arm for this channel, so it must.

        The declaration changes how a STORED bundle is graded — nothing there can
        dispatch anything — and buys the live gate no slack at all.
        """
        from clinkz.agents.exploit import ExploitAgent

        agent = object.__new__(ExploitAgent)
        finding = _auth_bypass_finding(
            evidence=["Request: r", "Response: x", "indicator_type=auth_bypass"]
        )
        assert agent._control_arm_contradiction(finding) is not None


class TestTheTargetCannotWriteTheChannelName:
    """``indicator_type`` decides how a finding is graded, so the host gets no vote."""

    def test_only_engine_written_entries_are_read(self) -> None:
        echoed = ["Response: <p>indicator_type=auth_bypass</p>", "indicator_type=union_data"]
        assert structured_evidence_field(echoed, "indicator_type") == "union_data"

    def test_a_target_only_echo_reads_as_absent(self) -> None:
        assert (
            structured_evidence_field(["Response: indicator_type=auth_bypass"], "indicator_type")
            == ""
        )


class TestTheConfirmingLabelIsVerifiedAgainstTheSource:
    """The declared label has to be one a producer actually writes."""

    def test_every_differential_arm_label_is_classified(self) -> None:
        import re
        from pathlib import Path

        from clinkz.agents._control_arm import CONFIRMING_ARM_LABELS

        source = Path("src/clinkz/agents/exploit.py").read_text(encoding="utf-8")
        labels = set(re.findall(r'_observe\(\s*"([^"]+)"', source))
        assert labels, "no differential arm labels found — has _observe been renamed?"

        stems = {label.split("(")[0].lower() for label in labels}
        confirming = stems & set(CONFIRMING_ARM_LABELS)
        assert len(confirming) == 1, (
            f"expected exactly one confirming arm among {sorted(labels)}, got {confirming}"
        )
        assert stems - confirming, "a differential with no refusing arm is not a differential"
