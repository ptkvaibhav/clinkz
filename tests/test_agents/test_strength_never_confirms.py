"""D1 batch-5 (G17): ``strength=likely`` can never reach a confirmed finding.

The G2 inversion, recurring. ``verification_strength`` is a methodology's own
statement of what it witnessed, and ``"likely"`` means the defining effect was
NOT observed — the DOM-XSS skill's docstring says so in as many words. But
``_make_finding`` stamps ``status=CONFIRMED`` unconditionally, so any class that
reached an emit with a ``likely`` result produced a finding contradicting itself
in its own evidence line: ``verified=True strength=likely`` under a confirmed
status.

It was fixed once, at the DOM-XSS dispatch. The batch-4 HIGH run then emitted::

    File Upload Validation Gap (client_side_only)   medium   confirmed
    phases_completed=6 verified=True strength=likely
    restrictions={'working_extensions': [], 'content_type_check': False,
                  'magic_byte_check': False, 'filename_injection_works': False}

— the oracle's own record that nothing executable worked, emitted as a confirmed
finding for a ``.jpg`` accepted exactly as designed. A codebase-wide audit found
two more live paths (reflected XSS in JS/DOM context, and the sqlmap fallback).

So the rule is asserted three ways here: structurally (every strength literal in
the module is classified), at the chokepoint (a ``likely`` finding is demoted
wherever it comes from), and per class (each source records a lead saying what
was missing).
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import (
    _CONFIRMING_VERIFICATION_STRENGTHS,
    _NON_CONFIRMING_VERIFICATION_STRENGTHS,
    ExploitAgent,
    _evidence_strength,
)
from clinkz.models.finding import UNPROVEN_WHY_UNCONFIRMED, Finding, FindingStatus, Severity
from clinkz.models.methodology import (
    FileUploadExecutionType,
    FileUploadRestrictions,
    JSAttackPatternType,
    JSAttacksMethodologyResult,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

EXPLOIT_SOURCE = Path(__file__).resolve().parents[2] / "src" / "clinkz" / "agents" / "exploit.py"

SCOPE = EngagementScope(
    name="strength-gate-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


def _make_agent() -> ExploitAgent:
    state = AsyncMock(spec=StateStore)
    state.add_finding = AsyncMock(return_value="finding-001")
    state.log_action = AsyncMock()
    agent = ExploitAgent(
        llm=None,  # type: ignore[arg-type]
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id="strength-gate-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._logger = logging.getLogger("test.strength")
    return agent


def _finding(strength: str) -> Finding:
    return Finding(
        title="Some Validation Gap",
        description="Technique: WSTG-BUSL-08. Parameter: file.",
        severity=Severity.MEDIUM,
        status=FindingStatus.CONFIRMED,
        target="http://t/app/upload/",
        evidence=[
            "Request: POST http://t/app/upload/ with profile_pic.jpg",
            "Response: upload accepted; payload retrievable at http://t/uploads/profile_pic.jpg",
            f"phases_completed=6 verified=True strength={strength}",
        ],
    )


# ===========================================================================
# Structural: no strength literal may be unclassified
# ===========================================================================


def _assigned_strength_literals() -> set[str]:
    """Every string literal assigned to ``verification_strength`` in exploit.py.

    Read from the AST rather than by grep so a conditional expression
    (``"verified" if ... else "verified-stored"``) yields BOTH branches — which
    is exactly the shape both live inversions had.
    """
    tree = ast.parse(EXPLOIT_SOURCE.read_text(encoding="utf-8"))
    literals: set[str] = set()

    def collect(node: ast.AST) -> None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            literals.add(node.value)
        elif isinstance(node, ast.IfExp):
            collect(node.body)
            collect(node.orelse)

    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Attribute) and target.attr == "verification_strength":
                if node.value is not None:
                    collect(node.value)
    return literals


class TestStrengthVocabularyIsClosed:
    def test_every_assigned_strength_is_classified(self) -> None:
        """A new label must be classified as confirming or not — never inherit
        "confirmed" by being unrecognised."""
        unclassified = sorted(
            value
            for value in _assigned_strength_literals()
            if value
            and value not in _CONFIRMING_VERIFICATION_STRENGTHS
            and value not in _NON_CONFIRMING_VERIFICATION_STRENGTHS
        )
        assert unclassified == [], f"unclassified verification_strength values: {unclassified}"

    def test_likely_is_classified_as_not_a_confirmation(self) -> None:
        assert "likely" in _NON_CONFIRMING_VERIFICATION_STRENGTHS
        assert "likely" not in _CONFIRMING_VERIFICATION_STRENGTHS

    def test_the_two_sets_are_disjoint(self) -> None:
        assert not (_CONFIRMING_VERIFICATION_STRENGTHS & _NON_CONFIRMING_VERIFICATION_STRENGTHS)

    def test_dom_redirect_stays_a_confirmation(self) -> None:
        """A blanket "anything that is not ``verified``" rule would demote a
        genuine finding: ``dom_redirect`` is a CHANNEL label on a witnessed
        body-level redirect to the attacker host, already de-rated to low
        severity and named in its own title."""
        assert "dom_redirect" in _CONFIRMING_VERIFICATION_STRENGTHS

    def test_strength_is_read_from_mid_line_evidence(self) -> None:
        """Methodologies render it into a line that starts with something else,
        so an anchored parse silently reads nothing and the gate never fires."""
        assert _evidence_strength(["phases_completed=6 verified=True strength=likely"]) == "likely"
        assert _evidence_strength(["strength=verified-oob"]) == "verified-oob"
        assert _evidence_strength(["no strength here"]) == ""


class TestTheTargetCannotDecideTheStrength:
    """The suppression primitive this gate would otherwise hand to a target.

    ``_make_finding`` builds evidence as ``["Request: …", "Response: …"]`` and
    the methodology appends its verdict AFTER — so the entry holding raw,
    unescaped bytes from the target sits at index 1, ahead of the engine's own
    ``strength=``. A first-match scan therefore reads the TARGET's bytes, and
    the value read decides whether the finding is demoted. A host echoing the
    literal ``strength=likely`` beside its reflection would delete a genuine,
    deterministically-confirmed finding from the report — the honesty rule
    running backwards, with bytes the target chose deciding an emission.
    """

    HOSTILE_REFLECTION = (
        "Response: <div><!--strength=likely--><pre>Hello <script>alert(1)</script></pre></div>"
    )

    def test_a_target_echoing_the_marker_cannot_lower_the_strength(self) -> None:
        evidence = [
            "Request: GET http://t/xss_r/ — name=<script>alert(1)</script>",
            self.HOSTILE_REFLECTION,
            "phases_completed=6 verified=True strength=verified",
        ]
        assert _evidence_strength(evidence) == "verified"

    async def test_a_target_echoing_the_marker_cannot_suppress_a_finding(self) -> None:
        agent = _make_agent()
        finding = _finding("verified")
        finding.evidence.insert(1, self.HOSTILE_REFLECTION)
        assert await agent._persist_finding(finding) is True
        assert agent._unproven_exploit_leads == []

    def test_a_rendered_structure_holding_the_marker_is_not_read(self) -> None:
        """An interior token that is not ``key=value`` disqualifies the entry, so
        target-derived text inside a rendered dict cannot be read as a verdict."""
        evidence = [
            "restrictions={'working_extensions': ['strength=likely'], 'magic': False}",
            "phases_completed=6 verified=True strength=verified",
        ]
        assert _evidence_strength(evidence) == "verified"

    def test_an_embedded_newline_cannot_forge_a_structured_entry(self) -> None:
        """Evidence entries are list ELEMENTS, not lines: a newline inside the
        captured response body does not start a new entry."""
        evidence = [
            "Response: <pre>x\nstrength=likely\n</pre>",
            "phases_completed=6 verified=True strength=verified",
        ]
        assert _evidence_strength(evidence) == "verified"

    def test_the_engine_verdict_is_still_read_when_it_says_likely(self) -> None:
        """Hardening the parse must not disarm the gate it protects."""
        evidence = [
            "Request: POST http://t/upload/",
            "Response: upload accepted; payload retrievable",
            "phases_completed=6 verified=True strength=likely",
        ]
        assert _evidence_strength(evidence) == "likely"


# ===========================================================================
# Chokepoint: the guard holds wherever the finding came from
# ===========================================================================


class TestEmissionChokepointDemotesLikely:
    async def test_a_likely_finding_is_demoted_to_a_lead(self) -> None:
        agent = _make_agent()
        emitted = await agent._persist_finding(_finding("likely"))
        assert emitted is False
        agent.state.add_finding.assert_not_awaited()

        leads = agent._unproven_exploit_leads
        assert len(leads) == 1
        assert leads[0].why_unconfirmed == "verification_strength_below_confirmation"
        assert leads[0].why_unconfirmed in UNPROVEN_WHY_UNCONFIRMED
        # The demotion must NAME the deterministic contradiction, not merely
        # assert one — that is the standing rule the suppression side runs under.
        assert "'likely'" in leads[0].missing_observation

    async def test_a_verified_finding_is_untouched(self) -> None:
        agent = _make_agent()
        assert await agent._persist_finding(_finding("verified")) is True
        assert agent._unproven_exploit_leads == []

    @pytest.mark.parametrize("strength", sorted(_CONFIRMING_VERIFICATION_STRENGTHS))
    async def test_every_confirming_strength_still_emits(self, strength: str) -> None:
        agent = _make_agent()
        assert await agent._persist_finding(_finding(strength)) is True

    async def test_a_finding_with_no_strength_line_is_untouched(self) -> None:
        """Posture methodologies (headers, CSRF) record no strength; the ground
        is "the finding says it is not confirmed", not "it did not say"."""
        agent = _make_agent()
        finding = _finding("verified")
        finding.evidence = finding.evidence[:2]
        assert await agent._persist_finding(finding) is True


# ===========================================================================
# Per class: the upload negative result (G17a)
# ===========================================================================


class TestUploadNegativeResultNeverConfirms:
    NEGATIVE = FileUploadRestrictions(
        working_extensions=[],
        content_type_check=False,
        magic_byte_check=False,
        filename_injection_works=False,
        image_carrier_extension=".jpg",
    )

    def test_the_batch4_high_fingerprint_is_a_negative_result(self) -> None:
        """Verbatim from the emitted finding's own ``restrictions=`` line."""
        assert ExploitAgent._file_upload_bypass_observed(self.NEGATIVE) is False

    def test_an_image_carrier_alone_is_not_a_bypass(self) -> None:
        """A store that takes ``x.jpg`` holding bytes is a store that takes
        images. Counting it produced a medium/confirmed finding on the one DVWA
        level whose upload control is doing its job."""
        assert self.NEGATIVE.image_carrier_extension == ".jpg"
        assert ExploitAgent._file_upload_bypass_observed(self.NEGATIVE) is False

    def test_an_enforced_check_is_a_defence_not_a_gap(self) -> None:
        enforcing = FileUploadRestrictions(
            working_extensions=[], content_type_check=True, magic_byte_check=True
        )
        assert ExploitAgent._file_upload_bypass_observed(enforcing) is False

    @pytest.mark.parametrize(
        "restrictions",
        [
            FileUploadRestrictions(working_extensions=[".php"]),
            FileUploadRestrictions(working_extensions=[".phtml"]),
            FileUploadRestrictions(filename_injection_works=True),
        ],
    )
    def test_a_witnessed_bypass_still_passes_the_gate(
        self, restrictions: FileUploadRestrictions
    ) -> None:
        assert ExploitAgent._file_upload_bypass_observed(restrictions) is True

    async def test_client_side_only_never_verifies_on_a_200_alone(self) -> None:
        """The exact line the phantom came from: ``fetch_resp.status == 200``."""
        agent = _make_agent()

        async def ok_post(*_args: Any, **_kwargs: Any) -> Any:
            return type(
                "R", (), {"status": 200, "body": "succesfully uploaded x.html", "headers": {}}
            )()

        async def ok_get(*_args: Any, **_kwargs: Any) -> Any:
            return type("R", (), {"status": 200, "body": "<html>clinkz</html>", "headers": {}})()

        agent._http_post_multipart = ok_post  # type: ignore[method-assign]
        agent._http_get = ok_get  # type: ignore[method-assign]

        verified, uploaded_url, observed = await agent._file_upload_phase5_verify(
            "http://t/app/upload/",
            {
                "filename": "clinkz_clientside.html",
                "content": "<html></html>",
                "content_type": "text/html",
                "canary": "clinkzcanary1",
            },
            FileUploadExecutionType.CLIENT_SIDE_ONLY,
        )
        assert verified is False
        assert uploaded_url is not None
        assert "no client-side execution was witnessed" in observed

    def test_the_no_bypass_lead_states_what_was_missing(self) -> None:
        agent = _make_agent()
        agent._file_upload_record_no_bypass_lead("http://t/app/upload/", "uploaded", self.NEGATIVE)
        assert len(agent._unproven_exploit_leads) == 1
        lead = agent._unproven_exploit_leads[0]
        assert lead.why_unconfirmed == "upload_accepted_but_no_restriction_bypass_observed"
        assert lead.why_unconfirmed in UNPROVEN_WHY_UNCONFIRMED
        assert "working_extensions=[]" in lead.raw_observation
        assert "restriction give way" in lead.missing_observation


# ===========================================================================
# G19 — the rationale must reflect the outcome actually reached
# ===========================================================================


class TestForgedTokenRationaleIsSelfConsistent:
    """The emitted forged-token finding read
    ``rationale="Bypass not feasible — non-literal write."`` while its own
    evidence read ``forge_confirmed=True`` — stale text from the pre-fix path,
    and precisely the self-inconsistent-evidence shape the FP detector hunts."""

    CLASSIFICATION = (
        "Hidden field(s) ['token'] populated by client-side JS. "
        "Bypass not feasible — non-literal write."
    )

    def test_a_confirmed_forge_overrides_the_prediction_that_it_was_infeasible(self) -> None:
        result = JSAttacksMethodologyResult(
            form_action="http://t/app/javascript/",
            form_method="POST",
            pattern_type=JSAttackPatternType.TOKEN_COMPUTATION,
            forge_attempted=True,
            forge_confirmed=True,
            forge_field="token",
        )
        reconciled = ExploitAgent._js_attacks_reconciled_rationale(self.CLASSIFICATION, result)
        assert "Classifier prediction:" in reconciled
        assert "ACCEPTED by the server" in reconciled
        # The prediction is preserved as an audit trail, but it no longer reads
        # as the finding's conclusion.
        assert reconciled.index("Classifier prediction") < reconciled.index("Outcome:")

    def test_an_unattempted_forge_says_so(self) -> None:
        result = JSAttacksMethodologyResult(
            form_action="http://t/app/x/",
            form_method="GET",
            pattern_type=JSAttackPatternType.HIDDEN_FIELD_WRITE,
            forge_unconfirmed_reason="no JS-controlled hidden field on a POST form",
        )
        reconciled = ExploitAgent._js_attacks_reconciled_rationale(self.CLASSIFICATION, result)
        assert "no forge was attempted" in reconciled
        assert "ACCEPTED" not in reconciled

    def test_an_attempted_but_rejected_forge_says_so(self) -> None:
        result = JSAttacksMethodologyResult(
            form_action="http://t/app/x/",
            form_method="POST",
            pattern_type=JSAttackPatternType.TOKEN_COMPUTATION,
            forge_attempted=True,
            forge_confirmed=False,
            forge_unconfirmed_reason="forged and control responses were identical",
        )
        reconciled = ExploitAgent._js_attacks_reconciled_rationale(self.CLASSIFICATION, result)
        assert "did not accept it" in reconciled
        assert "identical" in reconciled
