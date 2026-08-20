"""The client-ready report header, the honest-limits section, and the dry run."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.report import ReportAgent
from clinkz.engagement.dryrun import build_dry_run_plan, render_dry_run
from clinkz.models.engagement import CredentialSet, EngagementWindow, RoleCredential
from clinkz.models.report import NotTestedCategory, PentestReport
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.safety.action_log import ActionLog
from tests.authorization_fixtures import TEST_AUTHORIZATION

pytestmark = pytest.mark.asyncio


def _scope(**kwargs: object) -> EngagementScope:
    return EngagementScope(
        name="Acme Q3",
        targets=[ScopeEntry(value="https://app.test", type=ScopeType.URL)],
        excluded=[
            ScopeEntry(
                value="payments.app.test",
                type=ScopeType.DOMAIN,
                notes="production payment provider - no touch",
            )
        ],
        authorization=TEST_AUTHORIZATION,
        **kwargs,  # type: ignore[arg-type]
    )


def _agent(scope: EngagementScope, tmp_path: Path) -> ReportAgent:
    state = AsyncMock()
    state.get_findings.return_value = []
    state.get_targets.return_value = []
    state.get_research_leads.return_value = []
    return ReportAgent(
        llm=AsyncMock(),
        tools=[],
        scope=scope,
        state=state,
        engagement_id="eng-report",
    )


async def _render(scope: EngagementScope, tmp_path: Path, **extra: object) -> tuple[dict, str]:
    """Run the report agent and return (report dict, markdown).

    No ``chdir``: the suite-wide ``_redirect_outputs_root`` fixture already
    points every writer at this test's ``tmp_path``, so the paths the agent
    returns are absolute and resolve the same before and after. The previous
    version relied on the default root being the relative string ``outputs``
    and on the working directory being ``tmp_path`` at the moment the path was
    read — a coincidence, and one that hid whether the reader and the writer
    agreed on a root at all.
    """
    agent = _agent(scope, tmp_path)
    result = await agent.run(
        {
            "engagement_id": "eng-report",
            "engagement_name": scope.name,
            "authorization": scope.authorization.model_dump(mode="json"),
            "scope_in": [f"{t.value} ({t.type.value})" for t in scope.targets],
            "scope_out": [f"{e.value} ({e.type.value}) - {e.notes}" for e in scope.excluded],
            "rules_of_engagement": ["No testing during business hours"],
            "engagement_window": scope.window.model_dump(mode="json") if scope.window else None,
            **extra,
        }
    )
    markdown = Path(result["markdown_path"]).read_text(encoding="utf-8")
    return result["report"], markdown


# ---------------------------------------------------------------------------
# The header
# ---------------------------------------------------------------------------


async def test_the_authorization_record_is_in_the_report_header(tmp_path: Path) -> None:
    """A deliverable that cannot say who authorized the test is not a deliverable."""
    now = datetime.now(UTC)
    scope = _scope(
        window=EngagementWindow(start=now - timedelta(hours=1), end=now + timedelta(hours=4))
    )
    report, markdown = await _render(scope, tmp_path)

    assert report["authorization"]["authorizing_party"] == "Test Authorizer"
    assert "Test Authorizer" in markdown
    assert "TEST-SOW-0001" in markdown
    assert "oncall@example.test" in markdown
    assert "## Authorization" in markdown
    assert "## Engagement window" in markdown


async def test_out_of_scope_is_as_prominent_as_in_scope(tmp_path: Path) -> None:
    """'We did not touch X' is a statement the client is paying for."""
    _, markdown = await _render(_scope(), tmp_path)
    assert "Out of scope (never contacted)" in markdown
    assert "payments.app.test" in markdown
    assert "No testing during business hours" in markdown


async def test_safety_conduct_is_reported(tmp_path: Path) -> None:
    _, markdown = await _render(
        _scope(),
        tmp_path,
        safety={
            "max_requests_per_second": 3.0,
            "max_concurrent_requests": 2,
            "state_changing_sent": 7,
            "state_changing_refused": 4,
            "halted": False,
        },
    )
    assert "## Testing conduct" in markdown
    assert "3.0 requests/second" in markdown
    assert "State-changing requests sent:** 7" in markdown


async def test_a_halt_is_stated_in_the_report(tmp_path: Path) -> None:
    report, markdown = await _render(
        _scope(),
        tmp_path,
        safety={
            "halted": True,
            "halt_reason": "kill_switch",
            "halt_detail": "operator pulled the switch",
        },
    )
    assert "ENGAGEMENT HALTED" in markdown
    categories = {item["category"] for item in report["not_tested"]}
    assert NotTestedCategory.ENGAGEMENT_HALTED.value in categories


# ---------------------------------------------------------------------------
# What was NOT tested
# ---------------------------------------------------------------------------


async def test_no_findings_does_not_read_as_a_clean_bill_of_health(tmp_path: Path) -> None:
    _, markdown = await _render(_scope(), tmp_path)
    assert "No confirmed findings" in markdown
    assert "What was NOT tested" in markdown, (
        "an empty report must point the reader at what was and was not examined"
    )


async def test_the_named_unconfirmable_classes_are_listed(tmp_path: Path) -> None:
    """The brief's named cases: DOM-XSS / CSP, and Insecure CAPTCHA."""
    report, markdown = await _render(_scope(), tmp_path)
    items = {item["item"]: item for item in report["not_tested"]}

    dom = next(k for k in items if "DOM-based" in k)
    assert items[dom]["category"] == NotTestedCategory.NO_CLIENT_SIDE_ORACLE.value
    captcha = next(k for k in items if "CAPTCHA" in k)
    assert items[captcha]["category"] == NotTestedCategory.NOT_IMPLEMENTED.value

    assert "no client-side oracle" in markdown
    assert "no methodology" in markdown


async def test_excluded_scope_appears_in_not_tested(tmp_path: Path) -> None:
    report, _ = await _render(_scope(), tmp_path)
    out_of_scope = [
        item
        for item in report["not_tested"]
        if item["category"] == NotTestedCategory.OUT_OF_SCOPE.value
    ]
    assert out_of_scope
    assert "payments.app.test" in out_of_scope[0]["item"]


async def test_techniques_the_client_withheld_are_named(tmp_path: Path) -> None:
    narrow = TEST_AUTHORIZATION.model_copy(
        update={"permitted_techniques": ["sql_injection", "xss"]}
    )
    scope = _scope()
    scope.authorization = narrow
    report, markdown = await _render(scope, tmp_path)

    withheld = {
        item["item"]
        for item in report["not_tested"]
        if item["category"] == NotTestedCategory.NOT_PERMITTED.value
    }
    assert "OS Command Injection" in withheld
    assert "SQL Injection" not in withheld
    assert "Techniques not authorized" in markdown


async def test_refused_actions_are_reported_from_the_runs_own_action_log(
    tmp_path: Path,
    _redirect_outputs_root: Path,
) -> None:
    """Generated from the run's artifacts, so it cannot disagree with the run.

    The log is written to the same root the report agent RESOLVES, taken from
    the fixture rather than reconstructed as ``tmp_path / "outputs"``. Spelling
    it twice is what made this test a check on two literals matching instead of
    a check that the writer and the reader agree.
    """
    log = ActionLog("eng-report", outputs_root=_redirect_outputs_root)
    log.record_refused(
        method="POST",
        url="https://app.test/account/change-password",
        category="credential_change",
        reason="Request would overwrite authentication material.",
        signal="password",
    )
    report, markdown = await _render(_scope(), tmp_path)
    refused = [
        item
        for item in report["not_tested"]
        if item["category"] == NotTestedCategory.DESTRUCTIVE_REFUSED.value
    ]
    assert refused, "the report did not read the action log"
    assert "credential_change" in refused[0]["item"]
    assert "Refused by the production safety rails" in markdown


async def test_an_unauthenticated_run_says_so(tmp_path: Path) -> None:
    report, markdown = await _render(_scope(), tmp_path, authentication={"authenticated": False})
    unauth = [
        item
        for item in report["not_tested"]
        if item["category"] == NotTestedCategory.UNAUTHENTICATED.value
    ]
    assert unauth
    assert "only the surface reachable without a login" in unauth[0]["reason"]
    assert "NOT established" in markdown


async def test_a_single_role_run_flags_missing_cross_role_coverage(tmp_path: Path) -> None:
    report, _ = await _render(
        _scope(),
        tmp_path,
        authentication={
            "authenticated": True,
            "multi_role": False,
            "mechanism": "form",
            "roles": ["admin"],
            "assertion": {
                "discriminator": "status_class",
                "url": "https://app.test/",
                "authenticated_status": 200,
                "anonymous_status": 302,
                "evidence": ["anonymous redirected to /login"],
            },
        },
    )
    unauth = [
        item
        for item in report["not_tested"]
        if item["category"] == NotTestedCategory.UNAUTHENTICATED.value
    ]
    assert any("Cross-role" in item["item"] for item in unauth)


async def test_a_proven_session_is_shown_with_its_discriminator(tmp_path: Path) -> None:
    _, markdown = await _render(
        _scope(),
        tmp_path,
        authentication={
            "authenticated": True,
            "multi_role": True,
            "mechanism": "form",
            "roles": ["admin", "user"],
            "assertion": {
                "discriminator": "login_redirect",
                "url": "https://app.test/account",
                "authenticated_status": 200,
                "anonymous_status": 302,
                "evidence": ["anonymous GET redirected to /login; authenticated did not"],
            },
        },
    )
    assert "PROVEN" in markdown
    assert "login_redirect" in markdown
    assert "anonymous control HTTP 302" in markdown


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------


def test_dry_run_sends_nothing_and_says_what_it_would_do() -> None:
    plan = build_dry_run_plan(
        _scope(),
        CredentialSet(
            credentials=[
                RoleCredential(role="admin", username="a@app.test", password="aaaa1111"),
                RoleCredential(role="user", username="u@app.test", password="bbbb2222"),
            ]
        ),
    )
    assert plan.authorized
    assert plan.multi_role_available
    assert plan.roles == ["admin", "user"]
    assert any("payments.app.test" in entry for entry in plan.out_of_scope)
    assert plan.rails["max_requests_per_second"] == "5.0"

    text = render_dry_run(plan)
    assert "Nothing was sent" in text
    assert text.isascii(), "operator-facing output must survive any Windows console"


def test_dry_run_demonstrates_the_rails_rather_than_asserting_them() -> None:
    """The verdicts come from the real classifier, not a bullet list."""
    plan = build_dry_run_plan(_scope())
    assert plan.destructive_examples
    assert all(line.startswith("REFUSE") for line in plan.destructive_examples), (
        plan.destructive_examples
    )


def test_dry_run_warns_about_a_missing_authorization_and_anonymous_scanning() -> None:
    bare = EngagementScope(
        name="bare", targets=[ScopeEntry(value="app.test", type=ScopeType.DOMAIN)]
    )
    plan = build_dry_run_plan(bare)
    warnings = " ".join(plan.warnings)
    assert "NO AUTHORIZATION RECORD" in warnings
    assert "ANONYMOUSLY" in warnings


def test_dry_run_marks_unauthorized_classes_as_not_planned() -> None:
    scope = _scope()
    scope.authorization = TEST_AUTHORIZATION.model_copy(
        update={"permitted_techniques": ["sql_injection"]}
    )
    plan = build_dry_run_plan(scope)
    planned = {c.key for c in plan.classes if c.planned}
    assert planned == {"sql_injection"}
    skipped = {c.key: c.reason for c in plan.classes if not c.planned}
    assert "permitted-technique list" in skipped["command_injection"]


# ---------------------------------------------------------------------------
# The dry run's capability notes describe THIS machine, not a default one
# ---------------------------------------------------------------------------


def _dom_note(plan: object) -> str:
    """The capability note the dry run would print for DOM-based XSS."""
    return next(c.reason for c in plan.classes if c.key == "xss_dom")  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("available", "expected_fragment"),
    [
        (True, "IS available"),
        (False, "no client-side execution oracle"),
    ],
)
def test_the_client_oracle_note_reports_what_this_machine_actually_has(
    monkeypatch: pytest.MonkeyPatch, available: bool, expected_fragment: str
) -> None:
    """It used to state the oracle absent unconditionally.

    A pre-dispatch document that under-reports coverage is the same defect as
    one that over-reports it: on a docker-mode host with the tools image built,
    P7 confirms DOM-XSS, CSP bypass and client-side logic — and the operator was
    told to plan around a gap that was not there. Parametrised in both
    directions, because a note pinned only to the present case would pass
    against a version that ignores the probe and always says "IS available".
    """
    from clinkz.engagement import dryrun as dryrun_module

    monkeypatch.setattr(dryrun_module, "_client_oracle_present", lambda: available)
    plan = dryrun_module.build_dry_run_plan(_scope(), CredentialSet())
    assert expected_fragment in _dom_note(plan)


def test_an_unprobeable_client_oracle_reports_the_pessimistic_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dry run never fails, and never guesses upward, over a capability probe."""
    from clinkz.engagement import dryrun as dryrun_module

    def _boom() -> bool:
        raise RuntimeError("docker is not running")

    monkeypatch.setattr(
        "clinkz.browser.oracle.PlaywrightExecutionOracle.native_availability", _boom
    )
    assert dryrun_module._client_oracle_present() is False


# ---------------------------------------------------------------------------
# Both documents render from the same redacted structure
# ---------------------------------------------------------------------------


def _fingerprint(text: str) -> str:
    """The salted hash a redaction placeholder reports, or ``""``."""
    match = re.search(r"sha256=([0-9a-f]+)", text)
    return match.group(1) if match else ""


async def test_the_two_documents_agree_on_the_same_secret(tmp_path: Path) -> None:
    """A fingerprint that differs between report.json and report.md is broken.

    The fingerprint exists so occurrences of one secret CORRELATE inside a
    bundle while replaying nowhere. It failed at exactly that between the two
    primary documents, and the cause is the thing this test pins: JSON was built
    by redacting the STRUCTURE, Markdown by rendering the live report and
    string-scrubbing the result. By then the renderer's own punctuation is
    adjacent to the value, so the shape matcher took the trailing `)` of
    ``**HALTED** (...)`` to be part of the cookie and hashed something the JSON
    document never saw.

    The swallowed bracket is cosmetic. The mechanism is not: the same adjacency
    decides whether a shape matches AT ALL, and a redactor whose input is a
    formatted document is reading a string its own renderer composed.
    """
    secret = "sid=9f3a7c21e4bb48d0a15c6e77f2013b8e"
    report, markdown = await _render(
        _scope(),
        tmp_path,
        safety={
            "halted": True,
            "halt_reason": f"set-cookie: {secret}",
            "halt_detail": "operator aborted",
        },
    )

    assert secret not in markdown, "the secret itself reached the client's document"
    halt_line = next(line for line in markdown.splitlines() if "ENGAGEMENT HALTED" in line)
    assert _fingerprint(halt_line), halt_line
    assert _fingerprint(halt_line) == _fingerprint(report["safety_summary"]["halt_reason"]), (
        "report.md and report.json report different fingerprints for one secret"
    )
    assert halt_line.rstrip().endswith("operator aborted"), (
        "the renderer's own punctuation was absorbed into the redacted span"
    )


async def test_markdown_cannot_reach_a_value_the_json_path_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The structural guarantee, independent of what any renderer prints today.

    ``redact_structure`` is KEY-AWARE: a ``Set-Cookie`` value is removed on the
    strength of its key, which is the only thing identifying it — the target
    chose the value, so no string rule can recognise it. A renderer that reads
    from the live report can print such a value, and the string pass afterwards
    has no key left to go on.

    No renderer emits one TODAY, so this is not a leak that can be demonstrated
    end to end; it is gated by the current shape of the renderer rather than by
    anything structural. This asserts the structural half instead: whatever the
    renderer is handed carries no value the JSON document dropped. A new section
    printing a header dict cannot reopen it.
    """
    captured: list[PentestReport] = []
    original = ReportAgent._render_markdown

    def _capture(report: PentestReport, findings: list) -> str:
        captured.append(report)
        return original(report, findings)

    monkeypatch.setattr(ReportAgent, "_render_markdown", staticmethod(_capture))

    # A session cookie the TARGET minted: no vendor prefix, no JWT structure,
    # nothing a shape rule can key on. Only the header it arrived under says
    # what it is.
    secret = "8f14e45fceea167a5a36dedd4bea2543"
    await _render(
        _scope(),
        tmp_path,
        authentication={
            "authenticated": True,
            "mechanism": "form login",
            "roles": ["admin"],
            "assertion": {
                "discriminator": "session_marker",
                "set-cookie": f"JSESSIONID={secret}; Path=/; HttpOnly",
            },
        },
    )

    assert captured, "the markdown renderer was never called"
    rendered_from = json.dumps(captured[0].model_dump(mode="json"))
    assert secret not in rendered_from, (
        "the markdown renderer was handed a value key-aware redaction had removed"
    )
    # The NAME survives on purpose — a cookie name is evidence, its value is the
    # session — so this is not passing because the whole field was dropped.
    assert "JSESSIONID" in rendered_from
