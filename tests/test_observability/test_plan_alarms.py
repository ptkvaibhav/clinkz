"""The plan cap reaches the deliverable, and an inversion reads as an inversion.

The alarm itself is not new — ``_log_plan_truncation`` has named every dropped
class and every ranking inversion since D1 truncated ~1,500 candidates to 150
four times over. What was missing is that it landed only in the run log and
``trace.jsonl``, and a client reads neither. So a report could claim coverage
over a plan that dropped the one endpoint a class could have confirmed on.

Two properties:

* Truncation and ranking inversions are carried as **separate numbers** with
  separate renderings. They have different fixes — a larger cap covers a
  truncated tail and does nothing for a mis-ordered one — so summing them would
  hide the defect inside the budget.
* The section renders on a **clean** run too. A run that fit inside its cap and
  a run whose truncation nobody recorded must not produce identical artifacts.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from clinkz.agents.report import ReportAgent
from clinkz.models.report import PentestReport
from clinkz.observability.plan_alarms import (
    PlanAlarmRegister,
    PlanTruncation,
    get_active_plan_alarms,
    plan_alarm_summary,
    record_plan_truncation,
    set_active_plan_alarms,
)


@pytest.fixture
def register() -> PlanAlarmRegister:
    reg = PlanAlarmRegister()
    set_active_plan_alarms(reg)
    yield reg
    set_active_plan_alarms(None)


def _report(plan_coverage: dict[str, object]) -> PentestReport:
    now = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)
    return PentestReport(
        engagement_name="plan-alarm-test",
        test_start=now,
        test_end=now,
        plan_coverage=plan_coverage,
    )


def _render(report: PentestReport) -> str:
    lines: list[str] = []
    ReportAgent._render_plan_coverage(lines, report)
    return "\n".join(lines)


class TestAbsentByDefault:
    def test_no_register_installed_means_no_alarm_hook(self) -> None:
        """Byte-identical for a directly invoked methodology, a replay, a driver."""
        set_active_plan_alarms(None)
        assert get_active_plan_alarms() is None
        # Must not raise and must not create a register.
        record_plan_truncation(
            PlanTruncation(stage="deterministic", cap=150, kept=10, dropped_total=5)
        )
        assert get_active_plan_alarms() is None

    def test_the_clean_summary_shape_is_returned_with_no_register(self) -> None:
        set_active_plan_alarms(None)
        summary = plan_alarm_summary()
        assert summary["plan_truncated"] is False
        assert summary["passes_recorded"] == 0
        assert summary["ranking_inversion_count"] == 0


class TestTruncationAndInversionAreSeparate:
    def test_a_truncated_tail_reports_zero_inversions(self, register: PlanAlarmRegister) -> None:
        record_plan_truncation(
            PlanTruncation(
                stage="union",
                cap=150,
                kept=150,
                dropped_total=1350,
                dropped_by_class={"_test_sqli": ["https://example.com/a"]},
            )
        )
        summary = plan_alarm_summary()
        assert summary["plan_truncated"] is True
        assert summary["dropped_total"] == 1350
        assert summary["ranking_inversion_count"] == 0

    def test_an_inversion_is_counted_apart_from_the_drop_total(
        self, register: PlanAlarmRegister
    ) -> None:
        record_plan_truncation(
            PlanTruncation(
                stage="union",
                cap=150,
                kept=150,
                dropped_total=1350,
                dropped_by_class={"_test_weak_session": ["https://example.com/login"]},
                ranking_inversions=[
                    {
                        "test_method": "_test_weak_session",
                        "endpoint_url": "https://example.com/login",
                        "grade": 0,
                    }
                ],
            )
        )
        summary = plan_alarm_summary()
        assert summary["dropped_total"] == 1350
        assert summary["ranking_inversion_count"] == 1
        # The inversion is NOT folded into the drop total, and vice versa.
        assert summary["dropped_total"] != summary["ranking_inversion_count"]

    def test_a_ranking_failure_is_logged_at_warning(
        self, register: PlanAlarmRegister, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING"):
            record_plan_truncation(
                PlanTruncation(
                    stage="union",
                    cap=150,
                    kept=150,
                    dropped_total=1,
                    ranking_inversions=[
                        {"test_method": "_test_sqli", "endpoint_url": "/x", "grade": 0}
                    ],
                )
            )
        assert "PLAN RANKING FAILURE" in caplog.text

    def test_a_plain_truncation_does_not_log_a_ranking_failure(
        self, register: PlanAlarmRegister, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING"):
            record_plan_truncation(
                PlanTruncation(stage="union", cap=150, kept=150, dropped_total=900)
            )
        assert "RANKING FAILURE" not in caplog.text


class TestTheReportRendersIt:
    def test_a_clean_plan_still_gets_a_section(self, register: PlanAlarmRegister) -> None:
        record_plan_truncation(
            PlanTruncation(stage="deterministic", cap=150, kept=12, dropped_total=0)
        )
        rendered = _render(_report(plan_alarm_summary()))
        assert "## Plan coverage" in rendered
        assert "fit inside its task cap" in rendered

    def test_a_truncated_plan_names_the_classes_and_the_first_omitted_endpoint(
        self, register: PlanAlarmRegister
    ) -> None:
        record_plan_truncation(
            PlanTruncation(
                stage="union",
                cap=150,
                kept=150,
                dropped_total=42,
                dropped_by_class={
                    "_test_cmdi": ["https://example.com/exec", "https://example.com/run"]
                },
            )
        )
        rendered = _render(_report(plan_alarm_summary()))
        assert "42 candidate test(s)" in rendered
        assert "_test_cmdi" in rendered
        assert "https://example.com/exec" in rendered
        assert "The ordering held" in rendered

    def test_an_inversion_renders_as_an_ordering_defect_not_a_budget_one(
        self, register: PlanAlarmRegister
    ) -> None:
        record_plan_truncation(
            PlanTruncation(
                stage="union",
                cap=150,
                kept=150,
                dropped_total=42,
                dropped_by_class={"_test_weak_session": ["https://example.com/login"]},
                ranking_inversions=[
                    {
                        "test_method": "_test_weak_session",
                        "endpoint_url": "https://example.com/login",
                        "grade": 0,
                    }
                ],
            )
        )
        rendered = _render(_report(plan_alarm_summary()))
        assert "Ranking failure" in rendered
        assert "not a budget one" in rendered
        assert "raising the cap is not the" in rendered
        assert "https://example.com/login" in rendered
        # And it does not claim the ordering held.
        assert "The ordering held" not in rendered

    def test_a_report_with_no_recorded_pass_renders_nothing(self) -> None:
        """A directly invoked ReportAgent has no plan, and must not invent one."""
        set_active_plan_alarms(None)
        assert _render(_report(plan_alarm_summary())) == ""


class TestTheRecordIsBoundedButTheCountIsExact:
    def test_the_endpoint_list_is_capped_and_the_total_is_not(
        self, register: PlanAlarmRegister
    ) -> None:
        """A truncated record of a truncation is the failure this prevents."""
        endpoints = [f"https://example.com/{i}" for i in range(200)]
        record_plan_truncation(
            PlanTruncation(
                stage="union",
                cap=150,
                kept=150,
                dropped_total=200,
                dropped_by_class={"_test_xss": endpoints},
            )
        )
        summary = plan_alarm_summary()
        assert summary["dropped_total"] == 200
        rendered_endpoints = summary["passes"][0]["dropped_by_class"]["_test_xss"]
        assert len(rendered_endpoints) == 20
