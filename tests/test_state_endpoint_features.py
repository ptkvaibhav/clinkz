"""The endpoint round-trip that made a ranking replay unable to ask its question.

The Exploit planner ranks a (class, endpoint) pair on OBSERVED response features
(``sets_cookies`` / ``has_form`` / ``has_dom_source`` / ``session_setters``) and
on parameter STRUCTURE (``param_locations``). The endpoints table stored a URL,
a method and a flat parameter dict — so an Endpoint rebuilt from the store came
back with every one of those fields at its default.

A replay over recorded engagements therefore scored every candidate on absent
evidence and reported no change. That reads as "the ranking fix did nothing".
It actually means the question was never asked.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.agents.exploit import _is_observed_write_surface
from clinkz.models.scan import Endpoint, MethodEvidence, ParamLocation
from clinkz.state import StateStore


@pytest.fixture
async def store(tmp_path: Path) -> StateStore:
    async with StateStore(tmp_path / "t.db") as s:
        yield s


async def _engagement(store: StateStore) -> str:
    return await store.create_engagement("ranking-roundtrip", {"targets": []})


async def test_ranking_features_survive_the_round_trip(store: StateStore) -> None:
    """Every field the ranking reads must come back out of the store."""
    eid = await _engagement(store)
    ep = Endpoint(
        url="http://t/vulnerabilities/weak_id/",
        method="POST",
        params=["id", "body_field"],
        param_locations={"id": ParamLocation.COOKIE, "body_field": ParamLocation.JSON_BODY},
        session_setters=["http://t/session-input.php"],
        sets_cookies=["dvwaSession"],
        has_form=True,
        has_dom_source=True,
        content_type="application/json",
        method_evidence=MethodEvidence.NAMED,
    )

    await store.add_endpoint(
        engagement_id=eid,
        url=ep.url,
        method=ep.method,
        parameters=dict.fromkeys(ep.params, ""),
        features={
            "param_locations": {k: v.value for k, v in ep.param_locations.items()},
            "session_setters": ep.session_setters,
            "sets_cookies": ep.sets_cookies,
            "has_form": ep.has_form,
            "has_dom_source": ep.has_dom_source,
            "content_type": ep.content_type,
            "method_evidence": ep.method_evidence.value,
        },
    )

    (row,) = await store.get_endpoints(eid)
    assert row["param_locations"] == {"id": "cookie", "body_field": "json_body"}
    assert row["session_setters"] == ["http://t/session-input.php"]
    assert row["sets_cookies"] == ["dvwaSession"]
    assert row["has_form"] is True
    assert row["has_dom_source"] is True
    assert row["content_type"] == "application/json"
    assert row["method_evidence"] == "named"
    assert sorted(row["parameters"]) == ["body_field", "id"]

    # And it rebuilds into an Endpoint the ranking can actually score.
    rebuilt = Endpoint(
        url=row["url"],
        method=row["method"],
        params=sorted(row["parameters"]),
        param_locations={k: ParamLocation(v) for k, v in row["param_locations"].items()},
        session_setters=row["session_setters"],
        sets_cookies=row["sets_cookies"],
        has_form=row["has_form"],
        has_dom_source=row["has_dom_source"],
        content_type=row["content_type"],
        method_evidence=MethodEvidence(row["method_evidence"]),
    )
    assert rebuilt.param_locations == ep.param_locations
    assert rebuilt.has_dom_source is True
    assert rebuilt.method_evidence is MethodEvidence.NAMED


async def test_an_endpoint_written_without_features_reads_back_at_defaults(
    store: StateStore,
) -> None:
    """Backward compatibility: every existing caller passes no features."""
    eid = await _engagement(store)
    await store.add_endpoint(engagement_id=eid, url="http://t/a", discovered_by="scan")

    (row,) = await store.get_endpoints(eid)
    assert row["param_locations"] == {}
    assert row["sets_cookies"] == []
    assert row["has_form"] is False
    assert row["has_dom_source"] is False
    assert row["content_type"] == ""
    # The pessimistic default: a row written without a declared verb provenance
    # reads back as 'unread', never as a measured GET.
    assert row["method_evidence"] == "unread"


async def test_a_second_sighting_never_erases_an_observed_feature(
    store: StateStore,
) -> None:
    """Observed features OR-merge on dedup.

    Two crawl passes can reach the same URL. The pass that saw a form is
    evidence; a later pass that did not look is not counter-evidence, and
    letting it overwrite would make the ranking depend on visit order — the
    exact non-reproducibility the ranking rewrite exists to remove.
    """
    eid = await _engagement(store)
    await store.add_endpoint(
        engagement_id=eid,
        url="http://t/a",
        features={"has_form": True, "sets_cookies": ["SESSION"]},
    )
    await store.add_endpoint(engagement_id=eid, url="http://t/a", features={})

    (row,) = await store.get_endpoints(eid)
    assert row["has_form"] is True, "a second, blinder sighting erased the observation"
    assert row["sets_cookies"] == ["SESSION"]


async def test_a_later_sighting_can_add_a_feature_the_first_missed(
    store: StateStore,
) -> None:
    """The merge is a union, not a freeze."""
    eid = await _engagement(store)
    await store.add_endpoint(engagement_id=eid, url="http://t/a", features={"has_form": True})
    await store.add_endpoint(engagement_id=eid, url="http://t/a", features={"has_dom_source": True})

    (row,) = await store.get_endpoints(eid)
    assert row["has_form"] is True
    assert row["has_dom_source"] is True


async def test_method_evidence_survives_the_round_trip_so_part1_routing_holds(
    store: StateStore,
) -> None:
    """The seam Part 1 depends on: a NAMED write verb must survive the store.

    Observed-write routing keys on ``method_evidence``, not on the method string.
    If a store reload dropped the evidence (defaulting to UNREAD), a rebuilt POST
    endpoint would be excluded from every write-family class — so this asserts the
    rebuilt Endpoint both carries NAMED and is admitted by
    :func:`_is_observed_write_surface`, and that a verb-less store row (the old
    column default) is correctly NOT admitted.
    """
    eid = await _engagement(store)
    await store.add_endpoint(
        engagement_id=eid,
        url="http://t/api/Complaints",
        method="POST",
        features={"method_evidence": "named"},
    )
    # A row written with no provenance — the backward-compatible default.
    await store.add_endpoint(engagement_id=eid, url="http://t/api/legacy", method="POST")

    rows = {r["url"]: r for r in await store.get_endpoints(eid)}
    named = Endpoint(
        url=rows["http://t/api/Complaints"]["url"],
        method=rows["http://t/api/Complaints"]["method"],
        method_evidence=MethodEvidence(rows["http://t/api/Complaints"]["method_evidence"]),
    )
    legacy = Endpoint(
        url=rows["http://t/api/legacy"]["url"],
        method=rows["http://t/api/legacy"]["method"],
        method_evidence=MethodEvidence(rows["http://t/api/legacy"]["method_evidence"]),
    )
    assert named.method_evidence is MethodEvidence.NAMED
    assert _is_observed_write_surface(named), "a NAMED POST from the store must route to writes"
    assert legacy.method_evidence is MethodEvidence.UNREAD
    assert not _is_observed_write_surface(legacy), "a verb-less POST must stay excluded"


async def test_a_blind_re_sighting_never_downgrades_a_read_verb(
    store: StateStore,
) -> None:
    """'unread' is the weakest evidence, so a later pass that could not read the
    verb must not erase a NAMED one — the same OR-merge the other features use."""
    eid = await _engagement(store)
    await store.add_endpoint(
        engagement_id=eid, url="http://t/a", method="POST", features={"method_evidence": "named"}
    )
    # A second sighting that did not read the verb (default 'unread').
    await store.add_endpoint(engagement_id=eid, url="http://t/a", method="POST")

    (row,) = await store.get_endpoints(eid)
    assert row["method_evidence"] == "named", "a blind re-sighting downgraded a read verb"
