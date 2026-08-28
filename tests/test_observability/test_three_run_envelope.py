"""A variance envelope may only be computed out of runs that actually happened.

The 2026-08-25 envelope produced three bundles and one measurement. Run 1
dispatched 188 methodology tasks; runs 2 and 3 dispatched **zero**, because the
Anthropic account ran out of credit partway through the batch, and neither says
so anywhere a reader looks — ``2e21a200``'s ``provider_degradation`` block reports
``provider_degraded: false, baseline_eligible: true`` beside a ``model_stamp``
recording that nothing served recon, scan or exploit.

Two guards, asserted here on their outcomes rather than their wording:

* **before the batch** — a terminal account state refuses to start it. The
  condition is a property of the ACCOUNT and will hold for run 2 and run 3, so
  starting anyway manufactures void bundles;
* **after each run** — a run whose stamp names an unserved stage is not recorded
  and the batch stops. Excluded rather than caveated: an average over one real
  run and two dead ones is a wrong number, not a wider envelope.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from clinkz.llm.providers import DetectedProvider, KeyStatus, KeyValidation, ProviderPreflight

_SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


@pytest.fixture(scope="module")
def envelope() -> Any:
    added = str(_SCRIPTS) not in sys.path
    if added:
        sys.path.insert(0, str(_SCRIPTS))
    try:
        import three_run_envelope

        yield three_run_envelope
    finally:
        if added and str(_SCRIPTS) in sys.path:
            sys.path.remove(str(_SCRIPTS))


def _preflight(status: KeyStatus | None) -> ProviderPreflight:
    """A preflight whose priority-1 provider answered *status*, or has no key."""
    if status is None:
        return ProviderPreflight(
            detected=[], validations=[], priority=("anthropic",), keys_registered=0
        )
    return ProviderPreflight(
        detected=[
            DetectedProvider(
                name="anthropic",
                key_env="ANTHROPIC_API_KEY",
                model="claude-sonnet-5",
                model_from_env=False,
                key_length=100,
            )
        ],
        validations=[KeyValidation("anthropic", status, "credit balance is too low")],
        priority=("anthropic",),
        keys_registered=1,
    )


class TestTheTerminalAccountStateStopsTheBatch:
    """A depleted balance is not a busy minute; it holds for every run."""

    def test_a_refused_key_refuses_the_batch(
        self, envelope: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(envelope, "preflight_providers", _fake(_preflight(KeyStatus.INVALID)))
        preflight, refusal = envelope.preflight_gate()
        assert preflight is not None
        assert refusal, "an INVALID priority-1 key must refuse the batch"
        assert "ACCOUNT condition" in refusal

    def test_a_busy_provider_does_not_refuse_the_batch(
        self, envelope: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``UNREACHABLE`` is the provider having a minute and says nothing about
        the credential — the chain retries, and a three-hour batch should not die
        of a 429 at ``t=0``."""
        monkeypatch.setattr(
            envelope, "preflight_providers", _fake(_preflight(KeyStatus.UNREACHABLE))
        )
        _, refusal = envelope.preflight_gate()
        assert refusal == ""

    def test_a_valid_key_starts_the_batch(
        self, envelope: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(envelope, "preflight_providers", _fake(_preflight(KeyStatus.VALID)))
        _, refusal = envelope.preflight_gate()
        assert refusal == ""

    def test_no_key_at_all_refuses_the_batch(
        self, envelope: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(envelope, "preflight_providers", _fake(_preflight(None)))
        _, refusal = envelope.preflight_gate()
        assert "no key" in refusal

    def test_a_probe_that_cannot_run_refuses_rather_than_raising(
        self, envelope: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _boom() -> ProviderPreflight:
            raise RuntimeError("no providers detected")

        monkeypatch.setattr(envelope, "preflight_providers", _boom)
        preflight, refusal = envelope.preflight_gate()
        assert preflight is None
        assert "could not run" in refusal


class TestAVoidRunIsNotRecorded:
    """Excluded from the envelope, not carried with a caveat."""

    def test_the_batch_refuses_before_testing_on_a_terminal_state(
        self, envelope: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        launched: list[int] = []
        monkeypatch.setattr(envelope, "preflight_gate", lambda: (None, "credit balance too low"))
        monkeypatch.setattr(envelope, "run_once", lambda i, **_: launched.append(i))
        assert _main(envelope, monkeypatch, tmp_path, runs=3) == 3
        assert launched == [], "nothing may be sent once the batch has been refused"

    def test_an_exhausted_stamp_ends_the_batch_and_is_not_recorded(
        self, envelope: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        rows = [
            {
                "run": 1,
                "engagement": "aaa",
                "returncode": 0,
                "seconds": 1.0,
                "artifacts": "x",
                "exhausted_stages": [],
                "metrics": {"solved_total": 7, "findings_emitted": 7},
            },
            {
                "run": 2,
                "engagement": "bbb",
                "returncode": 0,
                "seconds": 1.0,
                "artifacts": "x",
                "exhausted_stages": ["exploit"],
                "metrics": {"solved_total": 4},
            },
            {
                "run": 3,
                "engagement": "ccc",
                "returncode": 0,
                "seconds": 1.0,
                "artifacts": "x",
                "exhausted_stages": ["exploit", "recon", "scan"],
                "metrics": {"solved_total": 4},
            },
        ]
        monkeypatch.setattr(envelope, "preflight_gate", lambda: (_preflight(KeyStatus.VALID), ""))
        monkeypatch.setattr(envelope, "run_once", lambda i, **_: dict(rows[i - 1]))
        out = tmp_path / "envelope"
        monkeypatch.setattr(envelope, "ENVELOPE_DIR", out)
        assert _main(envelope, monkeypatch, tmp_path, runs=3) == 4

        summary = json.loads((out / "envelope.json").read_text(encoding="utf-8"))
        assert summary["runs_attempted"] == 2, "the batch stops at the first void run"
        assert summary["runs_recorded"] == 1
        assert summary["aborted"] is True
        assert "exploit" in summary["abort_reason"]
        assert summary["attempts"][1]["recorded"] is False
        assert summary["variance"]["solved_total"]["values"] == [7], (
            "the void run's solved_total must not enter the envelope"
        )

    def test_a_run_that_produced_no_bundle_is_void_too(
        self, envelope: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """No bundle is not a clean run with nothing in it — there is nothing to read."""
        row = {
            "run": 1,
            "engagement": "",
            "returncode": 1,
            "seconds": 1.0,
            "artifacts": "x",
            "exhausted_stages": [],
            "void_reason": "the run produced no engagement bundle",
        }
        monkeypatch.setattr(envelope, "preflight_gate", lambda: (_preflight(KeyStatus.VALID), ""))
        monkeypatch.setattr(envelope, "run_once", lambda i, **_: dict(row))
        monkeypatch.setattr(envelope, "ENVELOPE_DIR", tmp_path / "envelope")
        assert _main(envelope, monkeypatch, tmp_path, runs=3) == 4


class TestTheVarianceIsOverRecordedRunsOnly:
    def test_a_metric_no_run_reported_is_null_not_zero(self, envelope: Any) -> None:
        spread = envelope.variance([{"run": 1, "metrics": {"solved_total": 7}}])
        assert spread["solved_total"] == {"values": [7], "min": 7, "max": 7, "runs": 1}
        assert spread["solved_by_testing_count"]["min"] is None
        assert spread["solved_by_testing_count"]["runs"] == 0

    def test_the_spread_is_reported_over_the_runs_that_reported_it(self, envelope: Any) -> None:
        spread = envelope.variance(
            [
                {"run": 1, "metrics": {"solved_total": 7, "methodology_dispatches": 188}},
                {"run": 2, "metrics": {"solved_total": 5, "methodology_dispatches": 150}},
            ]
        )
        assert spread["solved_total"] == {"values": [7, 5], "min": 5, "max": 7, "runs": 2}

    def test_an_empty_envelope_reports_nothing_rather_than_zeroes(self, envelope: Any) -> None:
        spread = envelope.variance([])
        assert all(metric["runs"] == 0 and metric["min"] is None for metric in spread.values())

    def test_every_metric_a_reconciliation_omits_is_null(self, envelope: Any) -> None:
        """The rule ``variance`` documents, checked at the producer of its input.

        ``findings_emitted`` was ``len(... or [])``, so an omitted key became
        ``0`` — past the ``is not None`` filter and into the envelope as an
        observation of a run that emitted nothing. The other three metrics keep
        the rule by doing nothing at all.
        """
        metrics = envelope.envelope_metrics({})
        assert set(metrics) == set(envelope.ENVELOPE_METRICS)
        assert all(value is None for value in metrics.values())
        assert envelope.variance([{"run": 1, "metrics": metrics}]) == {
            metric: {"values": [], "min": None, "max": None, "runs": 0}
            for metric in envelope.ENVELOPE_METRICS
        }

    def test_a_recorded_empty_list_is_still_a_measurement_of_zero(self, envelope: Any) -> None:
        """Absence and zero are different; only the first leaves the envelope."""
        metrics = envelope.envelope_metrics({"findings_emitted": [], "solved_total": 0})
        assert metrics["findings_emitted"] == 0
        assert metrics["solved_total"] == 0
        spread = envelope.variance([{"run": 1, "metrics": metrics}])
        assert spread["findings_emitted"]["runs"] == 1
        assert spread["findings_emitted"]["min"] == 0


def _fake(preflight: ProviderPreflight) -> Any:
    async def _run() -> ProviderPreflight:
        return preflight

    return _run


def _main(envelope: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, runs: int) -> int:
    """Drive ``main`` with the three operator files present and nothing else real."""
    paths = []
    for name in ("auth.json", "bp.json", "creds.json"):
        path = tmp_path / name
        path.write_text("{}", encoding="utf-8")
        paths.append(str(path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "three_run_envelope.py",
            "--authorization",
            paths[0],
            "--benchmark-profile",
            paths[1],
            "--creds",
            paths[2],
            "--runs",
            str(runs),
        ],
    )
    return envelope.main()
