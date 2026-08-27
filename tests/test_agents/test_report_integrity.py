"""The report may not contradict itself, and these are the three places it did.

Every claim here is one a client reads on the first page and has no way to check:
when the test ran, whether we were logged in, and what controlled the evidence.
A section that reads one field and states a conclusion the rest of the document
refutes is worse than a missing section — the client cannot tell it is wrong.

The guards are written the way the guard-domain law requires: the DOMAIN is
computed from the same source of truth as the thing it guards
(``CONTROL_EXEMPT_CLASSES``, ``TestingWindow``'s own producer), and only the
classification is hand-maintained. Both directions are asserted, so a new
exempt class fails the build and an entry that outlived its class does too.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from clinkz.agents._control_arm import (
    CONTROL_EXEMPT_CLASSES,
    control_required,
    declared_observation,
)
from clinkz.agents._report_integrity import (
    AuthenticationState,
    assert_testing_window_renderable,
    authentication_verdict,
    document_title,
    spend_cost_line,
)
from clinkz.agents._report_integrity import (
    TestingWindowError as _WindowError,  # pytest collects a module-level `Test*` name
)
from clinkz.agents._report_integrity import (
    testing_window as _window,  # ... and a module-level `test*` one, as a fixture request
)
from clinkz.models.finding import Finding, FindingStatus, Severity
from clinkz.models.report import PentestReport
from clinkz.models.vuln_classes import for_method

_T0 = datetime(2026, 8, 20, 16, 33, 17, tzinfo=UTC)


def _report(**overrides: object) -> PentestReport:
    base: dict[str, object] = {
        "engagement_name": "integrity-test",
        "target_scope": ["http://target.invalid:80 (url) — original_target=http://localhost:8080"],
        "test_start": _T0,
        "test_end": _T0,
        "generated_at": _T0,
    }
    base.update(overrides)
    return PentestReport.model_validate(base)


def _finding(**overrides: object) -> Finding:
    base: dict[str, object] = {
        "title": "SQL Injection in id parameter",
        "description": "Technique: WSTG-INPV-05. Parameter: id.",
        "severity": Severity.HIGH,
        "status": FindingStatus.CONFIRMED,
        "target": "http://target.invalid/vulnerabilities/sqli/",
        "evidence": ["Request: GET http://target.invalid/?id=1'"],
        "remediation": "Use parameterised queries.",
    }
    base.update(overrides)
    return Finding.model_validate(base)


# ---------------------------------------------------------------------------
# Part 1 — the testing window
# ---------------------------------------------------------------------------


class TestTheTestingWindowIsMeasuredNotGuessed:
    """``test_start == test_end`` on a 4,597s run, in both generated PDFs."""

    def test_a_stamped_window_is_the_one_that_renders(self) -> None:
        report = _report(
            safety_summary={
                "requests_authorized": 1488,
                "first_request_at": _T0.isoformat(),
                "last_request_at": (_T0 + timedelta(seconds=1582)).isoformat(),
            }
        )
        window = _window(report)
        assert window.recorded
        assert window.duration_seconds == pytest.approx(1582.0)
        assert "1,582s" in window.describe()

    def test_a_recovered_window_renders_its_provenance(self) -> None:
        """A window read back from the action log is NARROWER than the governor's.

        The log records state-changing requests and browser navigations, not
        every GET, so presenting it as the full window would be the same class of
        overstatement this whole module exists to remove.
        """
        report = _report(
            safety_summary={
                "requests_authorized": 1488,
                "first_request_at": _T0.isoformat(),
                "last_request_at": (_T0 + timedelta(seconds=1582)).isoformat(),
                "request_window_source": "recovered from this bundle's action log",
            }
        )
        assert "recovered from this bundle's action log" in _window(report).describe()

    def test_the_action_log_reader_recovers_a_window_or_nothing(self, tmp_path) -> None:
        """Half a window is a wrong claim; the renderer already says "not recorded"."""
        from clinkz.safety.action_log import request_window_from_log

        assert request_window_from_log(tmp_path / "absent.jsonl") is None
        one = tmp_path / "one.jsonl"
        one.write_text(json.dumps({"ts": "2026-08-20T16:33:17+00:00"}), encoding="utf-8")
        assert request_window_from_log(one) is None
        two = tmp_path / "two.jsonl"
        two.write_text(
            "\n".join(
                [
                    json.dumps({"ts": "2026-08-20T16:33:17+00:00"}),
                    "not json at all",
                    json.dumps({"ts": "2026-08-20T16:59:39+00:00"}),
                ]
            ),
            encoding="utf-8",
        )
        assert request_window_from_log(two) == (
            "2026-08-20T16:33:17+00:00",
            "2026-08-20T16:59:39+00:00",
        )

    def test_a_new_bundle_that_sent_requests_and_spans_no_time_fails_the_render(self) -> None:
        """The assertion the task asks for, at the seam it asks for it.

        A bundle written by this version always carries ``first_request_at``, so
        a degenerate window here is a defect rather than a missing record — and
        the document it would produce states a testing window taken from the
        report-generation clock, directly beneath the authorized window.
        """
        report = _report(
            safety_summary={
                "requests_authorized": 1488,
                "first_request_at": _T0.isoformat(),
                "last_request_at": _T0.isoformat(),
            }
        )
        with pytest.raises(_WindowError, match="spans no time"):
            assert_testing_window_renderable(report)

    def test_a_bundle_predating_the_stamp_says_not_recorded_rather_than_lying(self) -> None:
        """``clinkz report-pdf`` over an older bundle must stay usable.

        There is no honest value to substitute for a window nobody recorded, so
        the document states the absence — and explicitly says the timestamps it
        does carry are NOT evidence of when testing ran. It never renders a
        zero-length window as though it had been measured.
        """
        report = _report(safety_summary={"requests_authorized": 1488})
        window = assert_testing_window_renderable(report)
        assert not window.recorded
        assert "not recorded" in window.describe()
        assert "NOT" in window.describe()

    def test_a_run_that_dispatched_nothing_is_not_a_defect(self) -> None:
        """A dry run has no window, and that is the truthful answer."""
        report = _report(safety_summary={"requests_authorized": 0, "first_request_at": None})
        window = assert_testing_window_renderable(report)
        assert not window.requests_sent
        assert window.describe() == "no request was dispatched"

    def test_the_governor_stamps_only_authorized_requests(self) -> None:
        """A refused request is not a request the engagement made."""
        import asyncio

        from clinkz.models.engagement import SafetyPolicy
        from clinkz.safety.governor import EngagementGovernor

        governor = EngagementGovernor("wnd-test", SafetyPolicy(max_requests_per_second=1000.0))
        assert governor.first_request_at is None
        asyncio.run(governor.authorize("GET", "http://target.invalid/"))
        assert governor.first_request_at is not None
        stats = governor.stats()
        assert stats["first_request_at"] and stats["last_request_at"]


# ---------------------------------------------------------------------------
# Part 2 — the authentication contradiction
# ---------------------------------------------------------------------------


class TestTheAuthenticationRecordIsReconciled:
    """22 findings behind DVWA's login, under "NOT established"."""

    def test_findings_with_no_assertion_ever_run_is_inconsistent_not_negative(self) -> None:
        verdict = authentication_verdict({"authenticated": False, "assertion": None}, 22)
        assert verdict.state is AuthenticationState.INCONSISTENT
        assert not verdict.may_assert_no_session
        assert "session evidence present, record absent" in verdict.headline
        assert any("22 confirmed finding" in line for line in verdict.contradictions)

    def test_held_session_material_refutes_the_record_on_its_own(self) -> None:
        """The default-credential sweep's session, which never reached the record."""
        verdict = authentication_verdict(
            {
                "authenticated": False,
                "assertion": None,
                "session_material_held": True,
                "session_source": "the default-credential sweep",
            },
            0,
        )
        assert verdict.state is AuthenticationState.INCONSISTENT
        assert not verdict.may_assert_no_session

    def test_an_assertion_that_ran_and_failed_is_a_real_negative(self) -> None:
        """A negative claim IS allowed — when a check actually produced it."""
        verdict = authentication_verdict(
            {
                "authenticated": False,
                "assertion": {"established": False, "why_unproven": "no discriminator found"},
            },
            0,
        )
        assert verdict.state is AuthenticationState.DISPROVEN
        assert verdict.may_assert_no_session
        assert "no discriminator found" in verdict.headline

    def test_a_proven_session_is_unchanged(self) -> None:
        verdict = authentication_verdict(
            {"authenticated": True, "assertion": {"established": True}}, 7
        )
        assert verdict.state is AuthenticationState.PROVEN

    def test_the_sweep_registers_its_session_on_the_orchestrator(self) -> None:
        """The root cause: ``_attempt_login`` wrote to the credential store only.

        ``_role_sessions`` and ``_auth_assertion`` are the only two fields the
        report reads, and the sweep touched neither — so a run that was logged in
        for its whole duration reported that it had never logged in.
        """
        from unittest.mock import Mock

        from clinkz.orchestrator.orchestrator import SWEPT_CREDENTIAL_ROLE, OrchestratorAgent

        agent = OrchestratorAgent(llm=Mock())
        assert agent._authentication_summary()["session_material_held"] is False

        agent._register_swept_session("admin", "http://target.invalid/login.php", "apache")
        summary = agent._authentication_summary()
        assert summary["session_material_held"] is True
        assert any(SWEPT_CREDENTIAL_ROLE in role for role in summary["roles"])
        # PROVEN is a different claim and stays unearned: posting a password and
        # getting a cookie is the assumed-not-proven shape this codebase refuses.
        assert summary["authenticated"] is False
        assert not agent._role_session_handoff(), (
            "an unproven session must never travel as a principal an oracle can compare"
        )


# ---------------------------------------------------------------------------
# Part 3 — the control-arm page keeps its promise
# ---------------------------------------------------------------------------


def _exempt_classes_that_can_emit() -> set[str]:
    """Every control-exempt class a finding can actually resolve to.

    COMPUTED from the partition, not listed. ``_test_tier2_technique`` and
    ``_test_tier3_technique`` are excluded because they are not in
    ``_BY_METHOD`` at all — they construct no ``Finding`` (all three exits
    ``return []``), so no control-arm row can ever name them and ``for_finding``
    cannot resolve one.
    """
    return {method for method in CONTROL_EXEMPT_CLASSES if for_method(method) is not None}


class TestEveryExemptClassNamesTheRuleThatGovernsIt:
    """19 of 29 rows said only which rule does NOT apply."""

    def test_every_exempt_class_declares_a_governing_rule(self) -> None:
        undeclared = sorted(
            method
            for method in _exempt_classes_that_can_emit()
            if not (for_method(method).control_arm.governing_rule.strip())  # type: ignore[union-attr]
        )
        assert not undeclared, (
            f"{undeclared} are not bound by the never-sent-control rule and name no rule "
            "that does, so their rows can only report an absence"
        )

    def test_a_bound_class_declares_no_governing_rule(self) -> None:
        """The other direction: an entry that outlived what it described.

        A marker-bound class's row reports its DISPATCHED arm's verdict, so a
        governing_rule there would be a second, unread answer to the same
        question.
        """
        bound = sorted(
            method
            for method in {v.test_method for v in _all_dispatchable()}
            if control_required(method)
            and (vc := for_method(method)) is not None
            and vc.control_arm.governing_rule.strip()
        )
        assert not bound, f"{bound} are bound by the never-sent-control rule and declare a rule"

    def test_the_row_names_the_rule_and_the_observation(self) -> None:
        from clinkz.agents._report_pdf import control_arm_row

        row = control_arm_row(
            _finding(
                title="No Brute-Force Protection on http://target.invalid/login",
                description="Technique: WSTG-ATHN-03.",
                evidence=[
                    "Request: 8 rapid failed GET logins",
                    "Response: protection_type=none.",
                    "positive_control=all 8 attempts reached the authentication handler",
                ],
            )
        )
        assert row["outcome"] == "governed by its own rule"
        assert "POSITIVE control" in row["basis"]
        assert "positive_control=all 8 attempts reached the authentication handler" in row["basis"]

    def test_the_target_cannot_supply_the_observation(self) -> None:
        """Anchored at position 0 of an entry, which target bytes never occupy.

        Every entry carrying the host's own bytes is written by the engine with
        its ``Request: `` / ``Response: `` prefix. This is the same distinction
        that spared the juice-shop authentication bypass — ``startswith`` where
        ``re.search`` would have scanned into the target's text.
        """
        assert (
            declared_observation(
                ["Response: <b>positive_control=forged by the page</b>"], "positive_control"
            )
            == ""
        )

    def test_a_row_that_names_no_rule_fails_the_render(self) -> None:
        """The header promises the row will name the rule; a row that cannot, refuses."""
        from unittest.mock import patch

        from clinkz.agents._report_pdf import ControlArmRuleMissingError, control_arm_row
        from clinkz.models.vuln_classes import ControlArm

        vuln_class = for_method("_test_brute_force")
        assert vuln_class is not None
        stripped = vuln_class.model_copy(update={"control_arm": ControlArm()})
        finding = _finding(
            title="No Brute-Force Protection on http://target.invalid/login",
            description="Technique: WSTG-ATHN-03.",
        )
        with patch("clinkz.agents._report_pdf.for_finding", return_value=stripped):
            with pytest.raises(ControlArmRuleMissingError):
                control_arm_row(finding)


def _all_dispatchable() -> list:
    from clinkz.models.vuln_classes import DISCOVERY_CLASSES, VULN_CLASSES

    return [vc for vc in (*VULN_CLASSES, *DISCOVERY_CLASSES) if vc.test_method]


# ---------------------------------------------------------------------------
# Part 5 — the small ones
# ---------------------------------------------------------------------------


class TestTheSmallClaims:
    def test_an_unpriced_run_is_not_priced_rather_than_zero(self) -> None:
        line = spend_cost_line(
            {"usd_spent": 0.0, "usd_is_complete": False, "unpriced_models": ["claude-sonnet-5"]}
        )
        assert line.startswith("not priced")
        assert "claude-sonnet-5" in line
        assert "$0.00" not in line

    def test_a_partially_priced_run_states_a_floor(self) -> None:
        line = spend_cost_line(
            {"usd_spent": 1.25, "usd_is_complete": False, "unpriced_models": ["mystery-model"]}
        )
        assert line.startswith("at least $1.25")
        assert "LOWER BOUND" in line

    def test_a_fully_priced_run_is_a_plain_number(self) -> None:
        assert spend_cost_line({"usd_spent": 2.5, "usd_is_complete": True}) == "$2.50"

    def test_the_title_is_one_rule_for_both_bundles(self) -> None:
        """One PDF was titled by a scope label, the other by a URL."""
        labelled = _report(engagement_name="juiceshop-variance-envelope")
        assert document_title(labelled) == "juiceshop-variance-envelope — http://target.invalid:80"
        # The CLI names an engagement after its raw --target when no scope
        # document was supplied, so the label restates the target. It is dropped
        # rather than doubled — one rule, and the target is always named.
        bare = _report(engagement_name="http://target.invalid:80")
        assert document_title(bare) == "http://target.invalid:80"

    def test_the_title_never_carries_the_scope_entry_annotations(self) -> None:
        assert "original_target=" not in document_title(_report())
        assert "(url)" not in document_title(_report())
