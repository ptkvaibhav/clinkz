"""A control arm's outcome is the PROOF, and two consumers read it as the phantom.

An oracle that carries its own control renders the refusing arms beside the
confirming one, in one string. The juice-shop authentication bypass ships all
three at once::

    probe(tautology): status=200 body_token ...
      | control(contradiction): status=401 no auth artifact
      | benign: status=401 no auth artifact

Those two 401s are what make the 200 mean anything. Two consumers read them as
a failed request, and both landed on that same CRITICAL:

1. **The re-grade detector** called it ``NO_ARM``. It asks whether a class is
   marker-bound, which is declared per ``_test_*``; but ``_test_sqli`` confirms
   on five channels and ``auth_bypass`` is a three-arm differential whose
   contradiction and benign arms are DISPATCHED and must refuse. Neither the
   class name nor the indicator name carries that fact — ``_test_nosqli`` has an
   ``auth_bypass`` channel with no shape-matched contradiction at all — so the
   producer declares it and the consumer reads the declaration.
2. **The error-page ground** would have demoted it once moved to the
   unconditional emission chokepoint, reading those 401s as "the captured
   response was an HTTP error".

The second diagnosis was right and shallow. Attributing each status to an arm
fixed the two shapes that provoked it — the bypass and a confirmed chain's
``decoy_status=403`` — and left the actual defect standing: the ground was
reading the ``Response:`` evidence entry, which is where the **host under
test's** own bytes live. A target serving ``status=500``, ``stack trace`` or
``verified=False`` suppressed the finding proving its own vulnerability, and the
arm-aware reader made that easier rather than harder, since it scanned every
match per entry where ``re.search`` had stopped at the first.

So the fix went a level down: these grounds read only fields the ENGINE declared
(``response_status``, ``reflection_in_error_block``, ``verified``), through the
fully-structured reader a response body can never satisfy. Same rule, and the
same reason, as ``_evidence_strength``: a suppression primitive handed to the
target is worse than the phantom the guard prevents.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from clinkz.agents._control_arm import (
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


def _ground(finding: Finding) -> str | None:
    from clinkz.agents.exploit import ExploitAgent

    return object.__new__(ExploitAgent)._fp_ground_error_page(finding)


class TestTheGroundDoesNotReadTheTargetsBytes:
    """The `Response:` entry is where the host under test's own bytes live.

    Scanning it for `status=4xx` or an error-block marker hands the target a
    suppression primitive: serve `verified=False`, `status=500` or `stack trace`
    anywhere in a page and the finding proving your own vulnerability is demoted
    to a lead. Once every ground moved to the emission chokepoint that ran on
    every candidate with no model in the loop.
    """

    def test_a_target_cannot_suppress_with_a_status_string(self) -> None:
        finding = _auth_bypass_finding(
            evidence=[
                "Request: GET http://t/?q=probe",
                "Response: matched 'clinkzX' in body — <!-- status=500 --> checkout complete",
                "response_status=200",
            ]
        )
        assert _ground(finding) is None

    def test_a_target_cannot_suppress_with_an_error_block_marker(self) -> None:
        finding = _auth_bypass_finding(
            evidence=[
                "Request: GET http://t/?q=probe",
                "Response: matched 'clinkzX' in body — <!-- stack trace --> ok",
                "response_status=200",
            ]
        )
        assert _ground(finding) is None

    def test_a_target_cannot_suppress_with_verified_false(self) -> None:
        from clinkz.agents.exploit import ExploitAgent

        agent = object.__new__(ExploitAgent)
        finding = _auth_bypass_finding(
            evidence=[
                "Request: GET http://t/?q=probe",
                "Response: <input type=hidden name=state value='verified=False'>",
                "phases_completed=6 verified=True strength=verified",
            ]
        )
        assert agent._fp_ground_malformed_evidence(finding) is None

    def test_the_engines_own_declaration_still_fires(self) -> None:
        """Removing the primitive must not remove the guard's ability to fire."""
        finding = _auth_bypass_finding(
            evidence=["Request: r", "Response: reflected", "response_status=500"]
        )
        assert "HTTP error" in (_ground(finding) or "")
        block = _auth_bypass_finding(
            evidence=["Request: r", "Response: reflected", "reflection_in_error_block=True"]
        )
        assert "framework error block" in (_ground(block) or "")

    def test_the_engines_own_verified_false_still_fires(self) -> None:
        from clinkz.agents.exploit import ExploitAgent

        agent = object.__new__(ExploitAgent)
        finding = _auth_bypass_finding(
            evidence=[
                "Request: r",
                "Response: reflected",
                "phases_completed=5 verified=False strength=likely",
            ]
        )
        assert agent._fp_ground_malformed_evidence(finding) is not None


class TestTheShapesThatProvokedTheFix:
    """Both were read as failures; both are a control arm doing its job."""

    def test_the_authentication_bypass_is_not_demoted(self) -> None:
        finding = _auth_bypass_finding(
            evidence=[
                "Request: login request to http://t/rest/user/login",
                f"Response: {D8_OBSERVATION}",
                "indicator_type=auth_bypass",
            ]
        )
        assert _ground(finding) is None, (
            "the two 401s are the contradiction and benign arms REFUSING — the "
            "proof, not the phantom"
        )

    def test_a_confirmed_chain_is_not_demoted_by_its_own_decoy(self) -> None:
        chain = Finding(
            title="Confirmed attack chain — session token -> account takeover",
            description="Technique: chaining. Parameter: session_token.",
            severity=Severity.CRITICAL,
            status=FindingStatus.CONFIRMED,
            target="http://t/rest/user/whoami",
            evidence=["Request: Chain: a -> b", f"Response: {CHAIN_OBSERVATION}"],
        )
        assert _ground(chain) is None


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
