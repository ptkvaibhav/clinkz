"""The scope-refusal log — the control that used to leave no evidence.

A portfolio site links to GitHub and LinkedIn. The crawler follows links; the
scope check refuses the ones that leave the authorised host. That refusal is
the difference between testing the client and scanning a third party, and until
this log existed it produced no artifact at all — so a run that enforced it
perfectly and one that never had a link to follow were indistinguishable.
"""

from __future__ import annotations

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.safety.scope_refusals import (
    MAX_RETAINED,
    ScopeRefusalLog,
    record_scope_refusal,
    scope_refusal_summary,
    set_active_scope_refusal_log,
)
from clinkz.tools.http_client import HTTPClientTool
from tests.authorization_fixtures import TEST_AUTHORIZATION

SCOPE = EngagementScope(
    name="portfolio",
    targets=[ScopeEntry(value="ptkvaibhav.vercel.app", type=ScopeType.DOMAIN)],
    authorization=TEST_AUTHORIZATION,
)


@pytest.fixture
def log():
    active = ScopeRefusalLog()
    set_active_scope_refusal_log(active)
    yield active
    set_active_scope_refusal_log(None)


# ---------------------------------------------------------------------------
# The chokepoint records before it refuses
# ---------------------------------------------------------------------------


def test_the_tool_scope_check_records_the_refusal(log) -> None:
    tool = HTTPClientTool(scope=SCOPE, engagement_id="e", stage="scan")
    with pytest.raises(ValueError, match="outside the engagement scope"):
        tool._check_scope("https://github.com/ptkvaibhav")

    assert log.total == 1
    refusal = log.refusals()[0]
    assert refusal.target == "https://github.com/ptkvaibhav"
    assert refusal.host == "github.com"
    assert refusal.stage == "scan"
    assert refusal.tool == "HTTPClientTool"


def test_an_in_scope_target_records_nothing(log) -> None:
    tool = HTTPClientTool(scope=SCOPE, engagement_id="e", stage="scan")
    tool._check_scope("https://ptkvaibhav.vercel.app/about")
    assert log.total == 0


def test_the_refusal_still_raises(log) -> None:
    """The record must never displace the control it is recording."""
    tool = HTTPClientTool(scope=SCOPE, engagement_id="e", stage="scan")
    with pytest.raises(ValueError):
        tool._check_scope("https://www.linkedin.com/in/someone")


def test_recording_is_absent_by_default() -> None:
    """No log installed: byte-identical to before this existed."""
    set_active_scope_refusal_log(None)
    tool = HTTPClientTool(scope=SCOPE, engagement_id="e", stage="scan")
    with pytest.raises(ValueError):
        tool._check_scope("https://github.com/x")
    assert scope_refusal_summary()["total_refused"] == 0


# ---------------------------------------------------------------------------
# The tally
# ---------------------------------------------------------------------------


def test_hosts_are_tallied_most_refused_first(log) -> None:
    for _ in range(3):
        record_scope_refusal("https://github.com/a", stage="scan")
    record_scope_refusal("https://linkedin.com/b", stage="scan")
    assert list(log.hosts().items()) == [("github.com", 3), ("linkedin.com", 1)]


def test_a_bare_host_without_a_scheme_still_resolves(log) -> None:
    record_scope_refusal("cdn.example.com/asset.js")
    assert log.hosts() == {"cdn.example.com": 1}


def test_the_count_stays_exact_past_the_retention_cap(log) -> None:
    """A truncated tally would be the silent-cap failure this prevents."""
    for i in range(MAX_RETAINED + 25):
        record_scope_refusal(f"https://third-party.example/{i}")
    assert log.total == MAX_RETAINED + 25
    assert len(log.refusals()) == MAX_RETAINED

    rendered = log.to_dict()
    assert rendered["total_refused"] == MAX_RETAINED + 25
    assert rendered["truncated"] is True
    assert rendered["out_of_scope_hosts"] == {"third-party.example": MAX_RETAINED + 25}


# ---------------------------------------------------------------------------
# The clean case is a claim, not an absence
# ---------------------------------------------------------------------------


def test_a_clean_run_renders_the_claim(log) -> None:
    rendered = log.to_dict()
    assert rendered["total_refused"] == 0
    assert rendered["refusals"] == []
    assert rendered["truncated"] is False


def test_the_summary_shape_is_identical_with_no_log_installed() -> None:
    set_active_scope_refusal_log(None)
    assert scope_refusal_summary()["total_refused"] == 0


def test_every_refused_target_is_retained_verbatim(log) -> None:
    """The URL is the record. A host tally alone cannot answer "which link"."""
    targets = [
        "https://github.com/ptkvaibhav?tab=repositories",
        "https://www.linkedin.com/in/example/",
        "mailto:someone@example.com",
    ]
    for target in targets:
        record_scope_refusal(target, stage="scan")
    assert [r["target"] for r in log.to_dict()["refusals"]] == targets
