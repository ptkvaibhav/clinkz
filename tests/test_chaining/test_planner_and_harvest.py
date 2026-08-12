"""Planning and harvesting — what composes, in what order, out of what.

Two properties matter here and neither is about a single chain:

  * the harvester reads the class's DECLARED yield and nothing else, so it
    cannot invent an artifact a class never claimed; and
  * the plan order is a function of the finding SET, not of the order findings
    arrived in — findings come from a concurrent phase, so a tie broken by
    arrival order would make the engagement non-reproducible.
"""

from __future__ import annotations

import random

from clinkz.chaining.harvest import harvest_artifacts, is_internal_address
from clinkz.chaining.models import ChainArtifact, ChainKind
from clinkz.chaining.planner import CarriageSurface, ConfirmedStep, plan_chains
from clinkz.chaining.vocabulary import ArtifactKind

_SURFACE = CarriageSurface(
    login_endpoints=["https://app.test/rest/user/login"],
    session_probe_urls=["https://app.test/account"],
    fetch_channels=[("https://app.test/fetch", "url")],
    internal_targets=["http://127.0.0.1/", "http://169.254.169.254/"],
)


def _evidence(response: str, request: str = "GET /x") -> list[str]:
    return [f"Request: {request}", f"Response: {response}"]


# ---------------------------------------------------------------------------
# Harvesting reads the DECLARED yield
# ---------------------------------------------------------------------------


def test_a_class_that_declares_no_yield_harvests_nothing_however_suggestive() -> None:
    """A reflected-XSS body full of credential-looking bytes is still our own payload."""
    artifacts = harvest_artifacts(
        test_method="_test_xss_reflected",
        finding_id="f1",
        finding_title="Reflected XSS in q",
        evidence=_evidence('{"password": "hunter2xyz"}'),
        target="https://app.test/search",
    )
    assert artifacts == []


def test_secrets_exposure_harvests_the_credential_it_declares() -> None:
    artifacts = harvest_artifacts(
        test_method="_test_secrets_exposure",
        finding_id="f2",
        finding_title="Secret exposure in /config",
        evidence=_evidence('{"db_user": "svc", "db_password": "topsecret123"}'),
        target="https://app.test/config",
    )
    kinds = {a.kind for a in artifacts}
    assert ArtifactKind.CREDENTIAL in kinds
    credential = next(a for a in artifacts if a.kind is ArtifactKind.CREDENTIAL)
    assert credential.value == "topsecret123"
    assert credential.principal == "svc"
    assert credential.source_test_method == "_test_secrets_exposure"


def test_an_lfi_finding_yields_file_content_not_a_credential_directly() -> None:
    """The class declares FILE_CONTENT; turning it into a credential is the planner's job."""
    artifacts = harvest_artifacts(
        test_method="_test_lfi",
        finding_id="f3",
        finding_title="Local file inclusion in page",
        evidence=_evidence("root:x:0:0\nDB_PASSWORD=frompasswdfile"),
        target="https://app.test/?page=",
    )
    assert {a.kind for a in artifacts} == {ArtifactKind.FILE_CONTENT}


def test_a_token_we_ourselves_sent_is_not_harvested_as_one_the_target_issued() -> None:
    """Our own probe value returning is the reflection phantom, one rung up."""
    token = "abcdefghijklmnopqrstuvwxyz012345"
    artifacts = harvest_artifacts(
        test_method="_test_weak_session",
        finding_id="f4",
        finding_title="Weak session token",
        evidence=_evidence(f"echo {token}", request=f"GET /x?t={token}"),
        target="https://app.test/login",
    )
    assert all(a.value != token for a in artifacts)


def test_harvesting_is_bounded_per_finding() -> None:
    body = "\n".join(f"user{i}:secret{i:04d}" for i in range(40))
    artifacts = harvest_artifacts(
        test_method="_test_secrets_exposure",
        finding_id="f5",
        finding_title="Secret exposure",
        evidence=_evidence(body),
        target="https://app.test/dump",
    )
    assert len(artifacts) <= 4


def test_only_real_address_space_counts_as_internal() -> None:
    assert is_internal_address("http://127.0.0.1/")
    assert is_internal_address("http://169.254.169.254/latest/")
    assert is_internal_address("http://10.1.2.3:8080/x")
    # A NAME is not an address-space fact, so it is never claimed to be internal:
    # pointing a confirmed fetch at a host we merely believe is internal is the
    # one mistake the scope fence exists to prevent.
    assert not is_internal_address("http://internal.corp.example/")
    assert not is_internal_address("http://8.8.8.8/")
    assert not is_internal_address("not a url")


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------


def _credential_artifact(finding_id: str = "f-secrets") -> ChainArtifact:
    return ChainArtifact(
        kind=ArtifactKind.CREDENTIAL,
        value="topsecret123",
        principal="svc",
        source_finding_id=finding_id,
        source_test_method="_test_secrets_exposure",
        obtained_by="a 'db_password' field in the recovered content",
    )


def test_a_credential_composes_with_a_discovered_login_endpoint() -> None:
    steps = [
        ConfirmedStep(
            finding_id="f-secrets",
            test_method="_test_secrets_exposure",
            endpoint="https://app.test/config",
            title="Secret exposure in /config",
            severity="medium",
        )
    ]
    candidates = plan_chains(steps=steps, artifacts=[_credential_artifact()], surface=_SURFACE)
    assert [c.chain_kind for c in candidates] == [ChainKind.CREDENTIAL_TO_ACCESS]
    candidate = candidates[0]
    assert candidate.carriage_target == "https://app.test/rest/user/login"
    assert candidate.base_severity == "medium"
    # The carriage link starts unproven: until the decoy control has run the
    # composition IS an inference, and must grade as one.
    assert candidate.links[-1].confirmed is False
    assert candidate.links[-1].confirmation_primitive == "P4"


def test_recovered_file_content_becomes_a_credential_chain() -> None:
    steps = [
        ConfirmedStep(
            finding_id="f-lfi",
            test_method="_test_lfi",
            endpoint="https://app.test/?page=",
            title="Local file inclusion",
            severity="high",
        )
    ]
    content = ChainArtifact(
        kind=ArtifactKind.FILE_CONTENT,
        value='{"username": "dbuser", "password": "pgpass9911"}',
        source_finding_id="f-lfi",
        source_test_method="_test_lfi",
    )
    candidates = plan_chains(steps=steps, artifacts=[content], surface=_SURFACE)
    assert [c.chain_kind for c in candidates] == [ChainKind.FILE_READ_TO_CREDENTIAL]
    assert candidates[0].artifact.kind is ArtifactKind.CREDENTIAL
    assert candidates[0].artifact.principal == "dbuser"
    assert candidates[0].base_severity == "high"


def test_a_confirmed_fetch_composes_with_an_in_scope_internal_address() -> None:
    steps = [
        ConfirmedStep(
            finding_id="f-ssrf",
            test_method="_test_ssrf",
            endpoint="https://app.test/fetch",
            title="SSRF in url",
            severity="medium",
        )
    ]
    candidates = plan_chains(steps=steps, artifacts=[], surface=_SURFACE)
    assert candidates
    assert all(c.chain_kind is ChainKind.FETCH_TO_INTERNAL_REACH for c in candidates)
    assert candidates[0].carriage_parameter == "url"
    assert candidates[0].artifact.kind is ArtifactKind.INTERNAL_ENDPOINT


def test_no_carriage_surface_means_no_chain_rather_than_an_invented_destination() -> None:
    steps = [
        ConfirmedStep(
            finding_id="f-secrets",
            test_method="_test_secrets_exposure",
            endpoint="https://app.test/config",
            title="Secret exposure",
        )
    ]
    assert (
        plan_chains(steps=steps, artifacts=[_credential_artifact()], surface=CarriageSurface())
        == []
    )


def test_an_artifact_whose_source_finding_is_gone_plans_nothing() -> None:
    """A demoted head link cannot become a chain's head."""
    assert plan_chains(steps=[], artifacts=[_credential_artifact()], surface=_SURFACE) == []


def test_the_plan_order_is_a_function_of_the_finding_set_not_of_arrival_order() -> None:
    """Findings arrive from a concurrent phase; a tie broken by order is non-reproducible."""
    steps = [
        ConfirmedStep(
            finding_id="f-secrets",
            test_method="_test_secrets_exposure",
            endpoint="https://app.test/config",
            title="Secret exposure",
        ),
        ConfirmedStep(
            finding_id="f-ssrf",
            test_method="_test_ssrf",
            endpoint="https://app.test/fetch",
            title="SSRF in url",
        ),
        ConfirmedStep(
            finding_id="f-session",
            test_method="_test_weak_session",
            endpoint="https://app.test/login",
            title="Weak session token",
        ),
    ]
    artifacts = [
        _credential_artifact(),
        ChainArtifact(
            kind=ArtifactKind.SESSION_TOKEN,
            value="tokentokentokentoken1234",
            source_finding_id="f-session",
            source_test_method="_test_weak_session",
        ),
    ]

    def signature(seed: int) -> list[str]:
        rng = random.Random(seed)
        shuffled_steps = steps[:]
        shuffled_artifacts = artifacts[:]
        rng.shuffle(shuffled_steps)
        rng.shuffle(shuffled_artifacts)
        return [
            f"{c.chain_kind.value}@{c.carriage_target}"
            for c in plan_chains(
                steps=shuffled_steps, artifacts=shuffled_artifacts, surface=_SURFACE
            )
        ]

    signatures = {tuple(signature(seed)) for seed in range(12)}
    assert len(signatures) == 1, f"plan order varied with input order: {signatures}"


def test_impact_class_orders_the_plan_credential_access_first() -> None:
    steps = [
        ConfirmedStep(
            finding_id="f-secrets",
            test_method="_test_secrets_exposure",
            endpoint="https://app.test/config",
            title="Secret exposure",
        ),
        ConfirmedStep(
            finding_id="f-session",
            test_method="_test_weak_session",
            endpoint="https://app.test/login",
            title="Weak session",
        ),
    ]
    artifacts = [
        ChainArtifact(
            kind=ArtifactKind.SESSION_TOKEN,
            value="tokentokentokentoken1234",
            source_finding_id="f-session",
            source_test_method="_test_weak_session",
        ),
        _credential_artifact(),
    ]
    candidates = plan_chains(steps=steps, artifacts=artifacts, surface=_SURFACE)
    assert candidates[0].chain_kind is ChainKind.CREDENTIAL_TO_ACCESS


def test_the_candidate_list_is_bounded() -> None:
    steps = [
        ConfirmedStep(
            finding_id=f"f{i}",
            test_method="_test_secrets_exposure",
            endpoint=f"https://app.test/config{i}",
            title=f"Secret exposure {i}",
        )
        for i in range(30)
    ]
    artifacts = [
        ChainArtifact(
            kind=ArtifactKind.CREDENTIAL,
            value=f"secret{i:04d}",
            source_finding_id=f"f{i}",
            source_test_method="_test_secrets_exposure",
        )
        for i in range(30)
    ]
    assert len(plan_chains(steps=steps, artifacts=artifacts, surface=_SURFACE)) <= 8
