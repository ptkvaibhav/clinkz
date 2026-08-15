"""A recorded baseline without a model stamp is not a baseline.

Over 1,028 security-header analyses across 126 recorded engagements, the same
prompt on a byte-identical observation produced the version-disclosure entries in
27% of calls under ``claude-sonnet-5`` and 80% under ``claude-sonnet-4-6``. Any
figure graded against a previous run — a DVWA ladder finding count, a benchmark
coverage number — therefore moves when the model moves, with nothing in the
artifact recording that it did. The stamp is read from the calls the run actually
MADE, so a fallback shows the provider that answered rather than the one that was
configured.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.observability.trace import TraceWriter, set_active_trace_writer


@pytest.fixture(autouse=True)
def _no_leaked_active_writer():
    yield
    set_active_trace_writer(None)


def _writer(tmp_path: Path) -> TraceWriter:
    return TraceWriter("stamp-test", path_override=tmp_path / "trace.jsonl")


def _call(writer: TraceWriter, stage: str, provider: str, model: str) -> None:
    writer.llm_call(
        stage=stage,
        provider=provider,
        model=model,
        prompt_summary="p",
        response_summary="r",
    )


class TestModelStamp:
    def test_a_run_with_no_llm_calls_stamps_nothing(self, tmp_path: Path) -> None:
        """Empty is the honest rendering — never a fabricated default."""
        writer = _writer(tmp_path)
        assert writer.model_stamp() == []
        writer.close()

    def test_each_stage_records_the_model_that_served_it(self, tmp_path: Path) -> None:
        writer = _writer(tmp_path)
        _call(writer, "exploit", "anthropic", "claude-sonnet-5")
        _call(writer, "exploit", "anthropic", "claude-sonnet-5")
        _call(writer, "recon", "gemini", "gemini-3.1-flash-lite")

        assert writer.model_stamp() == [
            {
                "stage": "exploit",
                "provider": "anthropic",
                "model": "claude-sonnet-5",
                "calls": 2,
            },
            {
                "stage": "recon",
                "provider": "gemini",
                "model": "gemini-3.1-flash-lite",
                "calls": 1,
            },
        ]
        writer.close()

    def test_a_fallback_shows_both_models_for_the_stage(self, tmp_path: Path) -> None:
        """The one that answered is the one that shaped the output.

        Collapsing a stage to a single model would hide exactly the event this
        stamp exists to make visible: the configured provider was rate-limited
        and something else produced part of the run.
        """
        writer = _writer(tmp_path)
        for _ in range(3):
            _call(writer, "exploit", "anthropic", "claude-sonnet-5")
        _call(writer, "exploit", "gemini", "gemini-3.1-flash-lite")

        stamp = writer.model_stamp()
        assert [entry["model"] for entry in stamp] == [
            "claude-sonnet-5",  # ordered by descending call count within the stage
            "gemini-3.1-flash-lite",
        ]
        assert [entry["calls"] for entry in stamp] == [3, 1]
        writer.close()

    def test_the_stamp_counts_calls_not_distinct_models(self, tmp_path: Path) -> None:
        """A model that served once and one that served 500 times are not equal
        evidence about what produced the run."""
        writer = _writer(tmp_path)
        for _ in range(5):
            _call(writer, "scan", "gemini", "gemini-3.1-flash-lite")
        assert writer.model_stamp()[0]["calls"] == 5
        writer.close()


class TestReportCarriesTheStamp:
    def test_the_report_model_accepts_and_round_trips_it(self) -> None:
        from datetime import UTC, datetime

        from clinkz.models.report import PentestReport

        stamp = [
            {"stage": "exploit", "provider": "anthropic", "model": "claude-sonnet-5", "calls": 12}
        ]
        report = PentestReport(
            engagement_name="stamp",
            test_start=datetime.now(UTC),
            test_end=datetime.now(UTC),
            model_stamp=stamp,
        )
        assert report.model_stamp == stamp
        assert PentestReport.model_validate_json(report.model_dump_json()).model_stamp == stamp

    def test_a_report_defaults_to_an_empty_stamp_not_a_guess(self) -> None:
        from datetime import UTC, datetime

        from clinkz.models.report import PentestReport

        report = PentestReport(
            engagement_name="stamp",
            test_start=datetime.now(UTC),
            test_end=datetime.now(UTC),
        )
        assert report.model_stamp == []
