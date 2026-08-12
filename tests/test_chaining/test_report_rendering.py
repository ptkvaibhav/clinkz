"""What a chain looks like in the deliverable.

Two things a report must not do with a chain: count it twice, and render an
unproven composition as a confirmed one. Both are structural here — a chain
finding goes through the ordinary findings list and the composition view is a
separate field, and a chain lead is a different TYPE in a different field — but
"structural" is worth an assertion, because the rendering is where it would show.
"""

from __future__ import annotations

from datetime import UTC, datetime

from clinkz.agents.report import ReportAgent
from clinkz.models.engagement import (
    BENCHMARK_ACKNOWLEDGEMENT,
    AuthorizationRecord,
    BenchmarkProfile,
)
from clinkz.models.finding import ChainResearchLead, Finding, FindingStatus, Severity
from clinkz.models.report import ExecutiveSummary, PentestReport
from clinkz.safety.destructive import CATEGORY_UNSAFE_METHOD

_NOW = datetime.now(UTC)


def _chain_finding() -> Finding:
    return Finding(
        title="Confirmed attack chain — secrets_exposure → carriage(credential)",
        description="Technique: chaining. Parameter: credential.",
        severity=Severity.CRITICAL,
        status=FindingStatus.CONFIRMED,
        target="https://app.test/rest/user/login",
        evidence=[
            "Request: Chain: secrets_exposure → carriage(credential)",
            "Response: real_status=200 accepted=True | decoy_status=401 accepted=False",
        ],
    )


def _chain_view() -> dict[str, object]:
    return {
        "chain_kind": "credential_to_access",
        "severity": "critical",
        "base_severity": "medium",
        "composed_grade": "static_confirmed",
        "impact_statement": "a credential the application disclosed was accepted as authentication",
        "links": [
            {
                "ordinal": 1,
                "kind": "exploit",
                "test_method": "_test_secrets_exposure",
                "endpoint": "https://app.test/config",
                "confirmation_primitive": "P3",
                "description": "Secret exposure in /config",
            },
            {
                "ordinal": 2,
                "kind": "carriage",
                "test_method": "carriage:credential_to_access",
                "endpoint": "https://app.test/rest/user/login",
                "confirmation_primitive": "P4",
                "description": "the credential was accepted while the decoy was refused",
                "composition": {
                    "carried_kind": "credential",
                    "carried_fingerprint": "aaaa1111bbbb",
                    "decoy_fingerprint": "cccc2222dddd",
                    "decoy_shape": "same length, same character classes in the same positions",
                    "acceptance_signal": "the authenticated-state boundary discriminator flips",
                    "real_status": 200,
                    "real_accepted": True,
                    "decoy_status": 401,
                    "decoy_accepted": False,
                },
            },
        ],
    }


def _chain_lead() -> ChainResearchLead:
    return ChainResearchLead(
        candidate_chain="sqli → carriage(credential) @ https://app.test/login",
        why_unconfirmed="decoy_also_accepted_composition_not_discriminating",
        unconfirmed_link="link 2 (carriage of credential at https://app.test/login)",
        chain_kind="credential_to_access",
        carried_artifact_kind="credential",
        carried_artifact_fingerprint="eeee3333ffff",
        links=["1. exploit _test_sqli [P1/P2/P3] confirmed=True"],
        raw_observation="the carried credential was accepted and so was the decoy",
        missing_observation="a composition that discriminates on the VALUE, not the shape",
    )


def _report(**kwargs: object) -> PentestReport:
    findings = list(kwargs.pop("findings", []))  # type: ignore[arg-type]
    return PentestReport(
        engagement_name="Chaining render",
        target_scope=["app.test"],
        test_start=_NOW,
        test_end=_NOW,
        executive_summary=ExecutiveSummary.from_findings("overview", findings),
        findings=findings,
        **kwargs,  # type: ignore[arg-type]
    )


def test_a_confirmed_chain_is_counted_once_and_rendered_twice() -> None:
    """Once in the totals, once in the composition view — never counted twice."""
    finding = _chain_finding()
    report = _report(findings=[finding], confirmed_chains=[_chain_view()])
    markdown = ReportAgent._render_markdown(report, [finding])

    assert report.finding_counts["critical"] == 1
    assert "- **Confirmed findings:** 1" in markdown
    assert "already counted once" in markdown
    assert "## Confirmed attack chains — composition detail" in markdown


def test_the_composition_view_shows_the_decoy_control_a_reader_can_check() -> None:
    finding = _chain_finding()
    report = _report(findings=[finding], confirmed_chains=[_chain_view()])
    markdown = ReportAgent._render_markdown(report, [finding])

    assert "**Decoy control:**" in markdown
    assert "aaaa1111bbbb" in markdown
    assert "cccc2222dddd" in markdown
    assert "same character classes" in markdown
    assert "accepted=True" in markdown
    assert "accepted=False" in markdown
    # The escalation is shown as a delta, not as a number that appeared.
    assert "escalated from medium" in markdown


def test_an_unproven_chain_renders_in_its_own_unconfirmed_section() -> None:
    report = _report(findings=[], chain_leads=[_chain_lead()])
    markdown = ReportAgent._render_markdown(report, [])

    assert "## Unproven attack chains (candidate compositions — UNCONFIRMED)" in markdown
    assert "NOT findings" in markdown
    assert "decoy_also_accepted_composition_not_discriminating" in markdown
    assert "link 2 (carriage of credential" in markdown
    # And it is nowhere near the findings section.
    assert "## Findings" in markdown
    assert markdown.index("## Findings") < markdown.index("## Unproven attack chains")


def test_a_chain_lead_is_never_counted_in_the_totals() -> None:
    report = _report(findings=[], chain_leads=[_chain_lead()])
    assert report.finding_counts == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    markdown = ReportAgent._render_markdown(report, [])
    assert "- **Confirmed findings:** 0" in markdown
    assert "- **Unconfirmed leads:** 1 (not counted above)" in markdown


def test_a_run_with_no_chains_renders_no_chain_sections_but_still_states_zero() -> None:
    """A zero is information: chaining ran and composed nothing.

    That is exactly the distinction the contribution ledger exists to make, so
    the summary line stays even when the sections do not — a report that omits
    the line entirely reads as "chaining was not part of this engagement".
    """
    report = _report(findings=[])
    markdown = ReportAgent._render_markdown(report, [])
    assert "- **Confirmed attack chains:** 0" in markdown
    assert "## Confirmed attack chains — composition detail" not in markdown
    assert "## Unproven attack chains" not in markdown


def test_the_benchmark_profile_is_rendered_as_prominently_as_the_authorization() -> None:
    """A run in which destructive categories were permitted is a different run."""
    authorization = AuthorizationRecord(
        authorizing_party="Pratik Vaibhav",
        authorizing_role="Owner",
        authorizing_contact="p@example.test",
        authorization_reference="local-lab",
        permitted_techniques=["*"],
        emergency_contact="p@example.test",
        benchmark_profile=BenchmarkProfile(
            target_is_throwaway=True,
            acknowledgement=BENCHMARK_ACKNOWLEDGEMENT,
            permitted_categories=[CATEGORY_UNSAFE_METHOD],
            declared_by="Pratik Vaibhav",
            declared_reference="local-lab/juice-shop-throwaway",
        ),
    )
    report = _report(findings=[], authorization=authorization)
    markdown = ReportAgent._render_markdown(report, [])

    assert "BENCHMARK PROFILE ACTIVE" in markdown
    assert BENCHMARK_ACKNOWLEDGEMENT in markdown
    assert CATEGORY_UNSAFE_METHOD in markdown
    # And what it did NOT permit, so nobody reads it as "all rails off".
    assert "session_destruction" in markdown
    assert "clinkz actions" in markdown


def test_no_benchmark_profile_renders_no_benchmark_block() -> None:
    authorization = AuthorizationRecord(
        authorizing_party="A",
        authorizing_role="B",
        authorizing_contact="c@x.test",
        authorization_reference="SOW-1",
        permitted_techniques=["*"],
        emergency_contact="d@x.test",
    )
    report = _report(findings=[], authorization=authorization)
    markdown = ReportAgent._render_markdown(report, [])
    assert "BENCHMARK PROFILE" not in markdown
