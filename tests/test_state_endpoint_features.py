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

from clinkz.models.scan import Endpoint, ParamLocation
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
        },
    )

    (row,) = await store.get_endpoints(eid)
    assert row["param_locations"] == {"id": "cookie", "body_field": "json_body"}
    assert row["session_setters"] == ["http://t/session-input.php"]
    assert row["sets_cookies"] == ["dvwaSession"]
    assert row["has_form"] is True
    assert row["has_dom_source"] is True
    assert row["content_type"] == "application/json"
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
    )
    assert rebuilt.param_locations == ep.param_locations
    assert rebuilt.has_dom_source is True


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
