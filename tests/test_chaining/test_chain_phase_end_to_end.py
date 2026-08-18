"""The chain phase, end to end, against a scripted HTTP layer.

Each chain type is exercised twice against the SAME fixture application:

  1. the target accepts only the real artifact  -> the chain CONFIRMS, and the
     escalated finding appears alongside its component finding; and
  2. the target accepts anything of the right shape -> the chain does NOT
     confirm, a chain LEAD is recorded naming the link that stopped it, and no
     finding is emitted.

The second case is the one that matters. It is the endpoint that 200s on every
login, which is exactly what would turn "SQL injection disclosed some rows" into
"account takeover" in a report if the composition had no control.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import ExploitAgent, _HTTPResponse
from clinkz.chaining.models import ChainKind
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.finding import CHAIN_WHY_UNCONFIRMED, Finding, FindingStatus, Severity
from clinkz.models.scan import Endpoint, HTTPScanResult, ScanResult, ServiceScanResult
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="chaining",
    targets=[
        ScopeEntry(value="app.test", type=ScopeType.DOMAIN),
        ScopeEntry(value="127.0.0.1", type=ScopeType.IP),
    ],
)

LOGIN = "https://app.test/rest/user/login"
FETCH = "https://app.test/fetch"
ACCOUNT = "https://app.test/account"

RECOVERED_SECRET = "topsecret123"
RECOVERED_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIyIn0.c2lnbmF0dXJlYnl0ZXM"


class _SilentLLM(LLMClient):
    async def reason(self, messages: list[LLMMessage], tools: Any = None) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


def _scan_result() -> ScanResult:
    return ScanResult(
        target="app.test",
        service_scans=[
            ServiceScanResult(
                service_type="http",
                port=443,
                result=HTTPScanResult(
                    endpoints=[
                        Endpoint(url=LOGIN, method="POST", params=["email", "password"]),
                        Endpoint(url=ACCOUNT, method="GET", sets_cookies=["session"]),
                        Endpoint(url=FETCH, method="GET", params=["url"]),
                    ]
                ),
            )
        ],
    )


def _agent(*, accepts_anything: bool) -> ExploitAgent:
    """An agent whose HTTP layer is a scripted application.

    ``accepts_anything`` is the confounder under test: an application that
    answers every login with a session, every token with a page, and every fetch
    with content. A composition oracle without a control confirms on it.
    """
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="f-1")
    state.add_research_lead = AsyncMock()
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()

    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id="chaining",
        resolver=ToolResolver(),
        persistent_kb=None,
    )

    async def post_json(url: str, obj: dict[str, Any], method: str = "POST") -> _HTTPResponse:
        if url == LOGIN:
            supplied = str(obj.get("password", ""))
            if accepts_anything or supplied == RECOVERED_SECRET:
                return _HTTPResponse(
                    status=200,
                    body='{"authentication": {"token": "srv-issued"}}',
                    headers={"set-cookie": "session=abc; HttpOnly"},
                )
            return _HTTPResponse(status=401, body='{"error": "Invalid email or password."}')
        return _HTTPResponse(status=404, body="")

    async def http_get(
        url: str,
        params: dict[str, str],
        cookie_overrides: dict[str, str] | None = None,
        host_override: str | None = None,
    ) -> _HTTPResponse:
        if url == ACCOUNT:
            presented = (cookie_overrides or {}).get("session", "")
            if accepts_anything or presented == RECOVERED_TOKEN:
                return _HTTPResponse(status=200, body="<h1>Your account</h1>", headers={})
            return _HTTPResponse(
                status=200, body='<form><input type="password" name="pw"></form>', headers={}
            )
        if url == FETCH:
            requested = params.get("url", "")
            if accepts_anything or "127.0.0.1" in requested or "169.254" in requested:
                return _HTTPResponse(status=200, body="ami-id\nlocal-hostname\n", headers={})
            return _HTTPResponse(status=502, body="Could not resolve host", headers={})
        return _HTTPResponse(status=404, body="", headers={})

    agent._http_post_json = post_json  # type: ignore[method-assign]
    agent._http_get = http_get  # type: ignore[method-assign]
    return agent


def _secrets_finding() -> Finding:
    return Finding(
        title="Secret exposure in /config",
        description="Technique: WSTG-CONF-05. Parameter: (response body).",
        severity=Severity.MEDIUM,
        status=FindingStatus.CONFIRMED,
        target="https://app.test/config",
        evidence=[
            "Request: GET https://app.test/config",
            f'Response: {{"db_user": "svc", "db_password": "{RECOVERED_SECRET}"}}',
        ],
    )


def _session_finding() -> Finding:
    return Finding(
        title="Weak session management at /login",
        description="Technique: WSTG-SESS-02. Parameter: session.",
        severity=Severity.MEDIUM,
        status=FindingStatus.CONFIRMED,
        target=LOGIN,
        evidence=[
            "Request: GET https://app.test/login",
            f"Response: set-cookie session={RECOVERED_TOKEN}",
        ],
    )


def _ssrf_finding() -> Finding:
    return Finding(
        title="SSRF in url parameter",
        description="Technique: WSTG-INPV-19. Parameter: url.",
        severity=Severity.MEDIUM,
        status=FindingStatus.CONFIRMED,
        target=FETCH,
        evidence=[
            "Request: GET https://app.test/fetch?url=http://127.0.0.1/",
            "Response: fetched 200 from the supplied address",
        ],
    )


async def _run(agent: ExploitAgent, findings: list[Finding]) -> list[Finding]:
    for finding in findings:
        await agent._persist_finding(finding)
    return await agent._run_chain_phase(findings, _scan_result())


# ---------------------------------------------------------------------------
# CREDENTIAL_TO_ACCESS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_recovered_credential_that_works_confirms_the_chain() -> None:
    agent = _agent(accepts_anything=False)
    emitted = await _run(agent, [_secrets_finding()])

    assert len(emitted) == 1
    chain_finding = emitted[0]
    assert chain_finding.title.startswith("Confirmed attack chain")
    # The escalation: a medium disclosure composes into working access.
    assert chain_finding.severity is Severity.CRITICAL
    assert "escalated=True" in chain_finding.evidence[1]
    assert agent._chain_leads == []
    assert len(agent._confirmed_chains) == 1
    assert agent._confirmed_chains[0].chain_kind is ChainKind.CREDENTIAL_TO_ACCESS


@pytest.mark.asyncio
async def test_the_decoy_control_breaks_the_credential_chain_on_a_permissive_login() -> None:
    """THE control. An endpoint that issues a session to anything proves nothing."""
    agent = _agent(accepts_anything=True)
    emitted = await _run(agent, [_secrets_finding()])

    assert emitted == []
    assert agent._confirmed_chains == []
    assert len(agent._chain_leads) == 1
    lead = agent._chain_leads[0]
    assert lead.why_unconfirmed == "decoy_also_accepted_composition_not_discriminating"
    assert lead.why_unconfirmed in CHAIN_WHY_UNCONFIRMED
    assert "carriage" in lead.unconfirmed_link
    # The lead must not reproduce what the chain carried.
    assert RECOVERED_SECRET not in lead.model_dump_json()
    assert lead.carried_artifact_fingerprint


# ---------------------------------------------------------------------------
# TOKEN_TO_IMPERSONATION
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_recovered_token_that_is_honoured_confirms_the_chain() -> None:
    agent = _agent(accepts_anything=False)
    emitted = await _run(agent, [_session_finding()])

    assert len(emitted) == 1
    assert emitted[0].severity is Severity.HIGH
    assert agent._confirmed_chains[0].chain_kind is ChainKind.TOKEN_TO_IMPERSONATION
    assert "impersonation" in emitted[0].evidence[1]


@pytest.mark.asyncio
async def test_the_decoy_control_breaks_the_token_chain_on_a_permissive_page() -> None:
    agent = _agent(accepts_anything=True)
    emitted = await _run(agent, [_session_finding()])

    assert emitted == []
    assert len(agent._chain_leads) == 1
    assert (
        agent._chain_leads[0].why_unconfirmed
        == "decoy_also_accepted_composition_not_discriminating"
    )


# ---------------------------------------------------------------------------
# FETCH_TO_INTERNAL_REACH — the escalation the brief names
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_confirmed_fetch_that_reaches_an_internal_address_escalates() -> None:
    """Every SSRF so far proves the FETCH and stops. This is the second observation."""
    agent = _agent(accepts_anything=False)
    emitted = await _run(agent, [_ssrf_finding()])

    assert len(emitted) == 1
    assert emitted[0].severity is Severity.HIGH
    assert agent._confirmed_chains[0].chain_kind is ChainKind.FETCH_TO_INTERNAL_REACH
    assert "internal address" in emitted[0].evidence[1]
    assert "escalated=True" in emitted[0].evidence[1]


@pytest.mark.asyncio
async def test_the_decoy_control_breaks_the_fetch_chain_when_any_host_returns_content() -> None:
    """A fetch channel that answers a non-resolving decoy is echoing, not reaching."""
    agent = _agent(accepts_anything=True)
    emitted = await _run(agent, [_ssrf_finding()])

    assert emitted == []
    assert len(agent._chain_leads) >= 1
    assert all(
        lead.why_unconfirmed == "decoy_also_accepted_composition_not_discriminating"
        for lead in agent._chain_leads
    )


# ---------------------------------------------------------------------------
# The phase's own guarantees
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_chaining_never_suppresses_or_regrades_a_component_finding() -> None:
    """A chain ADDS. The components keep what their own oracles gave them."""
    agent = _agent(accepts_anything=False)
    component = _secrets_finding()
    emitted = await _run(agent, [component])

    assert component.severity is Severity.MEDIUM
    assert component.status is FindingStatus.CONFIRMED
    assert emitted and emitted[0].id != component.id


@pytest.mark.asyncio
async def test_a_demoted_finding_cannot_become_a_chain_head() -> None:
    agent = _agent(accepts_anything=False)
    demoted = _secrets_finding()
    await agent._persist_finding(demoted)
    demoted.status = FindingStatus.FALSE_POSITIVE

    emitted = await agent._run_chain_phase([demoted], _scan_result())
    assert emitted == []
    assert agent._confirmed_chains == []


@pytest.mark.asyncio
async def test_a_class_the_client_did_not_authorize_plans_no_chain() -> None:
    agent = _agent(accepts_anything=False)
    agent._permitted_techniques = ["sql_injection"]
    emitted = await _run(agent, [_secrets_finding()])
    assert emitted == []
    assert agent._chain_leads == []


@pytest.mark.asyncio
async def test_a_run_with_no_confirmed_findings_is_a_no_op() -> None:
    agent = _agent(accepts_anything=False)
    assert await agent._run_chain_phase([], _scan_result()) == []
    assert agent._chain_leads == []


@pytest.mark.asyncio
async def test_the_chain_finding_never_reproduces_the_carried_secret() -> None:
    agent = _agent(accepts_anything=False)
    emitted = await _run(agent, [_secrets_finding()])
    blob = emitted[0].model_dump_json()
    assert RECOVERED_SECRET not in blob
    # It is referenced by a salted fingerprint instead, so a reviewer can still
    # correlate it with the finding that recovered it.
    assert "fingerprint" in blob


@pytest.mark.asyncio
async def test_the_chain_planner_reports_its_contribution_to_the_ledger() -> None:
    """A composer that is invoked every run and composes nothing must be visible."""
    from clinkz.observability.ledger import ContributionLedger, set_active_ledger

    ledger = ContributionLedger(engagement_id="chaining")
    set_active_ledger(ledger)
    try:
        agent = _agent(accepts_anything=False)
        await _run(agent, [_secrets_finding()])
        records = {r.name: r for r in ledger.records()}
        assert "chain_planner" in records
        assert records["chain_planner"].invocations == 1
        assert records["chain_planner"].items_contributed >= 1
    finally:
        set_active_ledger(None)


@pytest.mark.asyncio
async def test_a_planner_that_composes_nothing_is_reported_as_silent_not_as_healthy() -> None:
    """The composer's own degradation shape: invoked, succeeded, contributed zero."""
    from clinkz.observability.ledger import (
        ContributionLedger,
        LedgerAlarm,
        set_active_ledger,
    )

    ledger = ContributionLedger(engagement_id="chaining")
    set_active_ledger(ledger)
    try:
        agent = _agent(accepts_anything=False)
        # A confirmed finding that yields an artifact, and NO carriage surface —
        # so the planner runs and composes nothing.
        finding = _secrets_finding()
        await agent._persist_finding(finding)
        await agent._run_chain_phase([finding], ScanResult(target="app.test"))
        record = next(r for r in ledger.records() if r.name == "chain_planner")
        assert record.invocations == 1
        assert record.items_contributed == 0
        assert LedgerAlarm.SILENT in record.alarms
    finally:
        set_active_ledger(None)


# ---------------------------------------------------------------------------
# Security-review regressions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_recovered_credential_is_registered_for_redaction() -> None:
    """A response excerpt must not carry the recovered secret into the report.

    ``ChainArtifact.value`` being excluded from serialisation stops the artifact
    ITSELF from rendering, but ``CompositionEvidence.real_excerpt`` quotes up to
    400 bytes of the carriage response verbatim — and a login endpoint that
    echoes the submitted password in its error message would put the recovered
    credential straight into report.json. The redaction chokepoint already
    covers material the OPERATOR supplied; this is its sibling, material the
    ENGAGEMENT captured, which no registry had heard of.
    """
    from clinkz.engagement.secrets import clear_secrets, redact

    clear_secrets()
    try:
        agent = _agent(accepts_anything=False)
        await agent._persist_finding(_secrets_finding())
        assert RECOVERED_SECRET not in redact(f"error: bad password {RECOVERED_SECRET}")
    finally:
        clear_secrets()


@pytest.mark.asyncio
async def test_a_recovered_document_is_not_registered_as_a_secret() -> None:
    """Registering an 8 KB body would make every writer substring-match on it."""
    from clinkz.engagement.secrets import clear_secrets, registered_secret_count

    clear_secrets()
    try:
        agent = _agent(accepts_anything=False)
        lfi = Finding(
            title="Local file inclusion in page",
            description="Technique: WSTG-ATHZ-01. Parameter: page.",
            severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
            target="https://app.test/?page=",
            evidence=[
                "Request: GET https://app.test/?page=../../etc/hosts",
                "Response: " + ("ordinary recovered document text " * 40),
            ],
        )
        await agent._persist_finding(lfi)
        assert agent._chain_artifacts, "the file-read class declares a FILE_CONTENT yield"
        assert registered_secret_count() == 0
    finally:
        clear_secrets()
