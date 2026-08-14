"""A zero that is correct must not read like a zero that is a defect.

Four route discoverers reported ``invocations=2, contributed=0`` on every DVWA
run and the ledger reported all four as SILENT — the alarm class that means "a
component ran and produced nothing", which is the shape of a real defect. On
DVWA it was the shape of a PHP application with no ``/api`` surface, no served
spec and no GraphQL endpoint. The recorded runs say so directly: 92 JavaScript
files were fetched and read on ``ad7a8aab``, and they contain no ``/api|/rest``
route tokens because there are none to contain.

A permanent alarm that is permanently wrong is worse than no alarm. But the
cure cannot be a component grading itself — "there was nothing to find" is
exactly what a broken reader would say. So the discriminator is how far the
component's own pipeline got, and these tests pin both directions: the correct
zero is demoted out of the alarm list, and the 100%-discard zero (the ffuf
shape) still alarms and cannot be talked away.
"""

from __future__ import annotations

import pytest

from clinkz.agents._route_discovery import DiscoveryReport
from clinkz.observability.ledger import ComponentKind, ContributionLedger, LedgerAlarm

# ---------------------------------------------------------------------------
# DiscoveryReport — the discriminator itself
# ---------------------------------------------------------------------------


class TestCorrectlyEmptyReason:
    def test_no_input_of_this_kind_is_correct(self) -> None:
        report = DiscoveryReport(inputs_examined=0, detail="target serves no script bundles")
        assert "no input of this kind" in report.correctly_empty_reason

    def test_input_read_but_nothing_of_this_shape_is_correct(self) -> None:
        """The DVWA case: real bundles, read in full, no /api route in them."""
        report = DiscoveryReport(
            inputs_examined=92,
            candidates_seen=0,
            detail="92 bundle(s), 214000 bytes scanned",
        )
        reason = report.correctly_empty_reason
        assert "read 92 input(s)" in reason
        assert "nothing of this shape" in reason

    def test_candidates_found_and_none_emitted_is_not_correct(self) -> None:
        """The ffuf shape: real input in, 100% discarded on the way out."""
        report = DiscoveryReport(inputs_examined=4, candidates_seen=37, endpoints_emitted=0)
        assert report.correctly_empty_reason == ""

    def test_a_contributing_discoverer_claims_nothing(self) -> None:
        report = DiscoveryReport(inputs_examined=4, candidates_seen=37, endpoints_emitted=12)
        assert report.correctly_empty_reason == ""


# ---------------------------------------------------------------------------
# The ledger's two lists
# ---------------------------------------------------------------------------


class TestLedgerSeparatesTheTwoZeroes:
    def test_a_declared_correct_zero_is_not_an_alarm(self) -> None:
        ledger = ContributionLedger("e")
        ledger.record(
            name="discoverer:graphql",
            kind=ComponentKind.DISCOVERER,
            items=0,
            not_applicable="no GraphQL endpoint answered at 4 conventional paths",
        )
        (record,) = ledger.records()
        assert record.alarms == []
        assert record.correctly_empty is True
        assert ledger.alarming() == []
        assert [r.name for r in ledger.correctly_empty()] == ["discoverer:graphql"]

    def test_an_undeclared_zero_still_alarms(self) -> None:
        """Silence is not a claim of correctness — the default stays SILENT."""
        ledger = ContributionLedger("e")
        ledger.record(name="discoverer:openapi", kind=ComponentKind.DISCOVERER, items=0)
        (record,) = ledger.records()
        assert LedgerAlarm.SILENT in record.alarms
        assert record.correctly_empty is False

    def test_one_examined_zero_among_many_correct_ones_still_alarms(self) -> None:
        """A single real defect must not be absorbed by its quiet neighbours."""
        ledger = ContributionLedger("e")
        for _ in range(3):
            ledger.record(
                name="discoverer:js_call_site",
                kind=ComponentKind.DISCOVERER,
                items=0,
                not_applicable="no bundles served",
            )
        ledger.record(name="discoverer:js_call_site", kind=ComponentKind.DISCOVERER, items=0)
        (record,) = ledger.records()
        assert record.successes == 4
        assert record.not_applicable == 3
        assert LedgerAlarm.SILENT in record.alarms

    def test_the_flag_cannot_talk_a_real_contribution_into_a_zero(self) -> None:
        ledger = ContributionLedger("e")
        ledger.record(
            name="discoverer:static_bundle",
            kind=ComponentKind.DISCOVERER,
            items=98,
            not_applicable="nothing to see here",
        )
        (record,) = ledger.records()
        assert record.items_contributed == 98
        assert record.not_applicable == 0
        assert record.correctly_empty is False

    def test_the_flag_cannot_talk_a_failure_into_a_correct_zero(self) -> None:
        ledger = ContributionLedger("e")
        ledger.record(
            name="discoverer:openapi",
            kind=ComponentKind.DISCOVERER,
            ok=False,
            not_applicable="nothing to see here",
        )
        (record,) = ledger.records()
        assert record.failures == 1
        assert record.not_applicable == 0
        assert LedgerAlarm.ALL_FAILED in record.alarms

    def test_a_dead_seam_outranks_a_correct_zero(self) -> None:
        """Structurally unable to contribute is never 'correctly found nothing'."""
        ledger = ContributionLedger("e")
        ledger.record_dead_seam(
            name="discoverer:mystery",
            kind=ComponentKind.DISCOVERER,
            note="declares no contribution_report()",
        )
        ledger.record(
            name="discoverer:mystery",
            kind=ComponentKind.DISCOVERER,
            items=0,
            not_applicable="nothing served",
        )
        (record,) = ledger.records()
        assert LedgerAlarm.DEAD_SEAM in record.alarms
        assert ledger.correctly_empty() == []

    def test_reasons_reach_report_json(self) -> None:
        ledger = ContributionLedger("e")
        ledger.record(
            name="discoverer:graphql",
            kind=ComponentKind.DISCOVERER,
            items=0,
            not_applicable="introspection is DISABLED; no operations guessed",
        )
        rendered = ledger.to_dict()
        assert rendered["summary"]["correctly_empty_components"] == 1
        assert rendered["summary"]["silent_components"] == 0
        assert rendered["correctly_empty"] == [
            {
                "component": "discoverer:graphql",
                "reasons": ["introspection is DISABLED; no operations guessed"],
            }
        ]

    def test_reasons_are_bounded(self) -> None:
        ledger = ContributionLedger("e")
        for i in range(40):
            ledger.record(
                name="discoverer:openapi",
                kind=ComponentKind.DISCOVERER,
                items=0,
                not_applicable=f"reason {i}",
            )
        (record,) = ledger.records()
        assert len(record.not_applicable_reasons) <= 8
        assert record.not_applicable == 40


# ---------------------------------------------------------------------------
# End-to-end through run_route_discovery
# ---------------------------------------------------------------------------


class _FakeDiscoverer:
    """A discoverer that declares, used to drive the runner."""

    def __init__(self, name: str, endpoints: list, report: DiscoveryReport) -> None:
        self.name = name
        self._endpoints = endpoints
        self._report = report

    async def discover(self, base_url, fetch):  # noqa: ANN001, ARG002
        return list(self._endpoints)

    def contribution_report(self) -> DiscoveryReport:
        return self._report


class _MuteDiscoverer:
    """A discoverer that declares nothing — the dead-seam negative control."""

    name = "mute"

    async def discover(self, base_url, fetch):  # noqa: ANN001, ARG002
        return []


async def _noop_fetch(url: str):  # noqa: ANN202, ARG001
    return None


@pytest.mark.asyncio
async def test_runner_records_the_declared_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    from clinkz.agents import _route_discovery as mod
    from clinkz.observability import ledger as ledger_mod

    ledger = ContributionLedger("e")
    ledger_mod.set_active_ledger(ledger)
    try:
        await mod.run_route_discovery(
            "http://t/",
            _noop_fetch,
            discoverers=[
                _FakeDiscoverer(
                    "graphql",
                    [],
                    DiscoveryReport(inputs_examined=0, detail="no GraphQL envelope"),
                )
            ],
        )
    finally:
        ledger_mod.set_active_ledger(None)

    (record,) = ledger.records()
    assert record.correctly_empty is True
    assert record.alarms == []
    assert "no GraphQL envelope" in record.not_applicable_reasons[0]


@pytest.mark.asyncio
async def test_a_non_declaring_discoverer_is_a_dead_seam_not_an_assumed_zero() -> None:
    """The producer declares, or the seam is loud. Never a getattr default."""
    from clinkz.agents import _route_discovery as mod
    from clinkz.observability import ledger as ledger_mod

    ledger = ContributionLedger("e")
    ledger_mod.set_active_ledger(ledger)
    try:
        await mod.run_route_discovery("http://t/", _noop_fetch, discoverers=[_MuteDiscoverer()])
    finally:
        ledger_mod.set_active_ledger(None)

    (record,) = ledger.records()
    assert LedgerAlarm.DEAD_SEAM in record.alarms
    assert record.correctly_empty is False


@pytest.mark.asyncio
async def test_the_shipped_discoverers_all_declare() -> None:
    """Every default discoverer answers the contract, so none is a dead seam."""
    from clinkz.agents._route_discovery import default_discoverers

    for discoverer in default_discoverers():
        report = discoverer.contribution_report()
        assert isinstance(report, DiscoveryReport), discoverer.name
