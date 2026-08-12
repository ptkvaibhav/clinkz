"""The decoy control — the thing that stops chaining manufacturing findings.

Every test here is one of two shapes:

  * the chain confirms end-to-end, and
  * **the same chain, with the artifact replaced by an equivalently-shaped
    decoy, does NOT confirm.**

The second is the point. Two confirmed findings do not imply the chain between
them, and a successful second request does not either — an endpoint that accepts
everything accepts our carried credential too. The decoy is what tells those
apart, so it gets a test per chain type rather than one generic test.
"""

from __future__ import annotations

import pytest

from clinkz.chaining.composition import (
    credentials_in,
    decoy_for,
    evaluate_composition,
    grade_chain,
    links_independently_confirmed,
)
from clinkz.chaining.impact import escalate
from clinkz.chaining.models import (
    ChainArtifact,
    ChainKind,
    ChainLink,
    ConfirmedChain,
    LinkKind,
)
from clinkz.chaining.vocabulary import ArtifactKind
from clinkz.discovery.models import SoundnessGrade
from clinkz.models.finding import CHAIN_WHY_UNCONFIRMED

# ---------------------------------------------------------------------------
# Fixtures — one artifact per chain type
# ---------------------------------------------------------------------------

_ARTIFACTS: dict[ChainKind, ChainArtifact] = {
    ChainKind.CREDENTIAL_TO_ACCESS: ChainArtifact(
        kind=ArtifactKind.CREDENTIAL,
        value="Sup3rS3cret!2024",
        principal="admin@app.test",
        label="credential for admin@app.test",
        source_finding_id="f-sqli",
        source_test_method="_test_sqli",
    ),
    ChainKind.FILE_READ_TO_CREDENTIAL: ChainArtifact(
        kind=ArtifactKind.CREDENTIAL,
        value="db-password-9911",
        principal="dbuser",
        label="credential for dbuser parsed out of a recovered config",
        source_finding_id="f-lfi",
        source_test_method="_test_lfi",
    ),
    ChainKind.TOKEN_TO_IMPERSONATION: ChainArtifact(
        kind=ArtifactKind.SESSION_TOKEN,
        value="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIyIn0.c2lnbmF0dXJlYnl0ZXM",
        label="session token issued at /login",
        source_finding_id="f-session",
        source_test_method="_test_weak_session",
    ),
    ChainKind.FETCH_TO_INTERNAL_REACH: ChainArtifact(
        kind=ArtifactKind.INTERNAL_ENDPOINT,
        value="http://169.254.169.254/latest/meta-data/",
        label="internal metadata address",
        source_finding_id="f-ssrf",
        source_test_method="_test_ssrf",
    ),
}

_SIGNAL = "the acceptance signal fixed by the planner before either request"


def _confirmed_links(kind: ChainKind) -> list[ChainLink]:
    """A head exploit link plus an as-yet-unproven carriage link."""
    return [
        ChainLink(
            ordinal=1,
            kind=LinkKind.EXPLOIT,
            test_method=_ARTIFACTS[kind].source_test_method,
            endpoint="https://app.test/vuln",
            finding_id=_ARTIFACTS[kind].source_finding_id,
            confirmation_primitive="P3",
            soundness=SoundnessGrade.STATIC_CONFIRMED,
            confirmed=True,
            description="the head step",
        ),
        ChainLink(
            ordinal=2,
            kind=LinkKind.CARRIAGE,
            test_method=f"carriage:{kind.value}",
            endpoint="https://app.test/login",
            confirmation_primitive="P4",
            soundness=SoundnessGrade.HYPOTHESIZED,
            consumed=_ARTIFACTS[kind].kind,
            confirmed=False,
            why_unconfirmed="the decoy-substitution control has not run",
        ),
    ]


def _evaluate(kind: ChainKind, *, real_accepted: bool, decoy_accepted: bool):
    artifact = _ARTIFACTS[kind]
    decoy_value, decoy_shape = decoy_for(artifact)
    return (
        artifact,
        decoy_value,
        evaluate_composition(
            artifact=artifact,
            decoy_value=decoy_value,
            decoy_shape=decoy_shape,
            acceptance_signal=_SIGNAL,
            real_accepted=real_accepted,
            real_status=200 if real_accepted else 401,
            real_body="welcome back" if real_accepted else "invalid credentials",
            decoy_accepted=decoy_accepted,
            decoy_status=200 if decoy_accepted else 401,
            decoy_body="welcome back" if decoy_accepted else "invalid credentials",
            salt="engagement-salt",
        ),
    )


# ---------------------------------------------------------------------------
# Each chain type: it confirms, AND the decoy breaks it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", list(ChainKind))
def test_each_chain_type_confirms_when_the_real_artifact_is_accepted(kind: ChainKind) -> None:
    _artifact, _decoy, verdict = _evaluate(kind, real_accepted=True, decoy_accepted=False)
    assert verdict.confirmed
    assert verdict.why_unconfirmed == ""
    assert verdict.evidence.real_accepted is True
    assert verdict.evidence.decoy_accepted is False
    # The evidence has to let a reviewer re-derive the verdict, not take it.
    assert verdict.evidence.decoy_shape
    assert verdict.evidence.acceptance_signal == _SIGNAL
    assert verdict.evidence.carried_fingerprint != verdict.evidence.decoy_fingerprint


@pytest.mark.parametrize("kind", list(ChainKind))
def test_the_decoy_substitution_control_breaks_each_chain_type(kind: ChainKind) -> None:
    """THE test. An endpoint that accepts the shape proves nothing about the value."""
    _artifact, _decoy, verdict = _evaluate(kind, real_accepted=True, decoy_accepted=True)
    assert not verdict.confirmed
    assert verdict.why_unconfirmed == "decoy_also_accepted_composition_not_discriminating"
    assert verdict.why_unconfirmed in CHAIN_WHY_UNCONFIRMED
    assert "accepts the SHAPE" in verdict.detail


@pytest.mark.parametrize("kind", list(ChainKind))
def test_a_refused_artifact_is_two_real_findings_that_do_not_compose(kind: ChainKind) -> None:
    _artifact, _decoy, verdict = _evaluate(kind, real_accepted=False, decoy_accepted=False)
    assert not verdict.confirmed
    assert verdict.why_unconfirmed == "carried_artifact_not_accepted"
    assert "do not compose" in verdict.detail


# ---------------------------------------------------------------------------
# The decoy itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", list(ChainKind))
def test_the_decoy_is_equivalently_shaped_and_never_the_real_value(kind: ChainKind) -> None:
    """A control that differs in shape tests the shape, not the value."""
    artifact = _ARTIFACTS[kind]
    decoy, shape = decoy_for(artifact)
    assert decoy != artifact.value
    assert shape
    if artifact.kind is not ArtifactKind.INTERNAL_ENDPOINT:
        assert len(decoy) == len(artifact.value)
        for real_char, decoy_char in zip(artifact.value, decoy, strict=True):
            assert real_char.isdigit() == decoy_char.isdigit()
            assert real_char.isupper() == decoy_char.isupper()
            assert real_char.islower() == decoy_char.islower()
            if not real_char.isalnum():
                assert real_char == decoy_char, "separators must survive"


def test_a_jwt_decoy_keeps_the_three_segment_structure() -> None:
    artifact = _ARTIFACTS[ChainKind.TOKEN_TO_IMPERSONATION]
    decoy, _ = decoy_for(artifact)
    assert decoy.count(".") == artifact.value.count(".") == 2
    assert [len(s) for s in decoy.split(".")] == [len(s) for s in artifact.value.split(".")]


def test_an_internal_url_decoy_resolves_nowhere_but_keeps_the_scheme_and_port() -> None:
    """The decoy host must not be another address — that would probe a real host.

    An IP-literal decoy (``10.0.0.6`` for ``10.0.0.5``) would be closer in shape
    and much worse in effect: it could reach a live internal service the client
    never authorised. A reserved ``.invalid`` name cannot resolve, so the control
    fails for the reason intended.
    """
    from urllib.parse import urlsplit

    artifact = ChainArtifact(
        kind=ArtifactKind.INTERNAL_ENDPOINT, value="http://10.0.0.5:8080/admin/status"
    )
    decoy, shape = decoy_for(artifact)
    parts = urlsplit(decoy)
    original = urlsplit(artifact.value)
    assert parts.scheme == original.scheme
    assert parts.port == original.port
    assert (parts.hostname or "").endswith(".clinkz-decoy.invalid")
    assert parts.path.count("/") == original.path.count("/")
    assert "resolves nowhere" in shape


def test_the_decoy_is_deterministic_so_two_runs_build_the_same_control() -> None:
    artifact = _ARTIFACTS[ChainKind.CREDENTIAL_TO_ACCESS]
    assert decoy_for(artifact) == decoy_for(artifact)


def test_an_empty_artifact_has_no_control_and_is_refused() -> None:
    with pytest.raises(ValueError, match="empty artifact"):
        decoy_for(ChainArtifact(kind=ArtifactKind.CREDENTIAL, value=""))


# ---------------------------------------------------------------------------
# The carried value never reaches anything a human reads
# ---------------------------------------------------------------------------


def test_the_carried_value_is_excluded_from_serialisation() -> None:
    """A chain carries exactly the material a report must not reproduce."""
    artifact = _ARTIFACTS[ChainKind.CREDENTIAL_TO_ACCESS]
    dumped = artifact.model_dump()
    assert "value" not in dumped
    assert artifact.value not in str(dumped)
    assert artifact.value not in artifact.describe("salt")


def test_the_fingerprint_is_salted_and_correlates_within_a_bundle() -> None:
    artifact = _ARTIFACTS[ChainKind.CREDENTIAL_TO_ACCESS]
    assert artifact.fingerprint("a") != artifact.fingerprint("b")
    assert artifact.fingerprint("a") == artifact.fingerprint("a")
    assert artifact.value not in artifact.fingerprint("a")


def test_the_composition_evidence_never_carries_the_secret() -> None:
    artifact, decoy, verdict = _evaluate(
        ChainKind.CREDENTIAL_TO_ACCESS, real_accepted=True, decoy_accepted=False
    )
    blob = verdict.model_dump_json()
    assert artifact.value not in blob
    assert decoy not in blob, "even the decoy is referenced by fingerprint, not by value"


# ---------------------------------------------------------------------------
# "Every link independently confirmed" is checked, not trusted
# ---------------------------------------------------------------------------


def test_a_link_resting_on_inference_makes_the_whole_chain_a_lead() -> None:
    links = _confirmed_links(ChainKind.CREDENTIAL_TO_ACCESS)
    links[1].confirmed = True
    links[1].why_unconfirmed = ""
    links[0].confirmed = False
    links[0].why_unconfirmed = "inferred from a version banner"
    unconfirmed = links_independently_confirmed(links)
    assert unconfirmed is not None
    assert "link 1" in unconfirmed
    assert "inferred from a version banner" in unconfirmed


def test_a_confirmed_flag_with_no_oracle_named_is_not_a_confirmed_link() -> None:
    """A boolean nobody cross-checked is a convention, not a proof."""
    links = _confirmed_links(ChainKind.CREDENTIAL_TO_ACCESS)
    links[1].confirmed = True
    links[0].confirmation_primitive = ""
    unconfirmed = links_independently_confirmed(links)
    assert unconfirmed is not None
    assert "cites no P1" in unconfirmed


def test_a_fully_confirmed_chain_passes_the_gate() -> None:
    links = _confirmed_links(ChainKind.CREDENTIAL_TO_ACCESS)
    links[1].confirmed = True
    links[1].why_unconfirmed = ""
    assert links_independently_confirmed(links) is None


def test_a_multi_primitive_class_satisfies_the_gate() -> None:
    links = _confirmed_links(ChainKind.CREDENTIAL_TO_ACCESS)
    links[0].confirmation_primitive = "P1/P2/P3"
    links[1].confirmed = True
    assert links_independently_confirmed(links) is None


def test_an_empty_chain_is_not_a_chain() -> None:
    assert links_independently_confirmed([]) == "the chain has no links at all"


# ---------------------------------------------------------------------------
# Grading: min-over-composition, reusing the cross-service function
# ---------------------------------------------------------------------------


def test_a_chain_is_graded_by_its_weakest_link() -> None:
    links = _confirmed_links(ChainKind.CREDENTIAL_TO_ACCESS)
    assert links[0].soundness is SoundnessGrade.STATIC_CONFIRMED
    links[1].soundness = SoundnessGrade.HYPOTHESIZED
    assert grade_chain(links) is SoundnessGrade.HYPOTHESIZED


def test_a_cross_service_hop_dominates_every_other_grade() -> None:
    links = _confirmed_links(ChainKind.FETCH_TO_INTERNAL_REACH)
    links[1].soundness = SoundnessGrade.CROSS_SERVICE_TOPOLOGY
    assert grade_chain(links) is SoundnessGrade.CROSS_SERVICE_TOPOLOGY


# ---------------------------------------------------------------------------
# Impact escalation is a function of the demonstration, not of the chain kind
# ---------------------------------------------------------------------------


def _chain(kind: ChainKind, *, confirmed: bool, base: str = "medium") -> ConfirmedChain:
    links = _confirmed_links(kind)
    links[1].confirmed = confirmed
    links[1].soundness = (
        SoundnessGrade.STATIC_CONFIRMED if confirmed else SoundnessGrade.HYPOTHESIZED
    )
    return ConfirmedChain(chain_kind=kind, links=links, base_severity=base)


def test_a_confirmed_fetch_chain_escalates_a_medium_to_high() -> None:
    chain = _chain(ChainKind.FETCH_TO_INTERNAL_REACH, confirmed=True, base="medium")
    escalation = escalate(chain, base_severity="medium")
    assert escalation.severity == "high"
    assert escalation.escalated
    assert "internal address" in escalation.statement


def test_a_confirmed_credential_chain_escalates_to_critical() -> None:
    escalation = escalate(
        _chain(ChainKind.CREDENTIAL_TO_ACCESS, confirmed=True, base="high"),
        base_severity="high",
    )
    assert escalation.severity == "critical"
    assert escalation.escalated


def test_an_unconfirmed_chain_never_escalates() -> None:
    """Escalation is a function of the demonstration, so a candidate demonstrates nothing."""
    escalation = escalate(
        _chain(ChainKind.CREDENTIAL_TO_ACCESS, confirmed=False, base="medium"),
        base_severity="medium",
    )
    assert escalation.severity == "medium"
    assert not escalation.escalated
    assert "not escalated" in escalation.statement


def test_a_chain_never_lowers_a_severity_a_single_link_already_earned() -> None:
    """The components keep what their own oracles gave them."""
    escalation = escalate(
        _chain(ChainKind.TOKEN_TO_IMPERSONATION, confirmed=True, base="critical"),
        base_severity="critical",
    )
    assert escalation.severity == "critical"
    assert not escalation.escalated


def test_a_chain_with_no_carriage_link_demonstrates_no_composition() -> None:
    chain = ConfirmedChain(
        chain_kind=ChainKind.CREDENTIAL_TO_ACCESS,
        links=[_confirmed_links(ChainKind.CREDENTIAL_TO_ACCESS)[0]],
    )
    escalation = escalate(chain, base_severity="high")
    assert escalation.severity == "high"
    assert "no composition link" in escalation.statement


# ---------------------------------------------------------------------------
# Parsing an artifact out of recovered content
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("content", "expected_secret"),
    [
        ('{"username": "svc", "password": "hunter2xyz"}', "hunter2xyz"),
        ("DB_PASSWORD=topsecret123", "topsecret123"),
        ("postgres://appuser:pgpass9911@db.internal:5432/app", "pgpass9911"),
        ("admin:$1$abcd$efghijklmnop", "$1$abcd$efghijklmnop"),
    ],
)
def test_credentials_are_parsed_only_from_shapes_that_name_them(
    content: str, expected_secret: str
) -> None:
    secrets = [c.secret for c in credentials_in(content)]
    assert expected_secret in secrets


def test_a_high_entropy_string_is_not_a_credential_just_because_it_looks_like_one() -> None:
    """Nothing is inferred from entropy — a wrong guess is a login attempt for nothing."""
    assert credentials_in("build 7f3a9c1e2b4d6088aa11ff2233445566778899aabbccddeeff") == []


def test_credential_parsing_is_bounded_and_deterministic() -> None:
    content = "\n".join(f"user{i}:secret{i:04d}" for i in range(50))
    first = credentials_in(content)
    assert len(first) <= 3
    assert [c.secret for c in first] == [c.secret for c in credentials_in(content)]
