"""The governor's five rails, each proven by its own observable effect."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from clinkz.models.engagement import EngagementWindow, SafetyPolicy
from clinkz.safety.action_log import ActionLog
from clinkz.safety.governor import (
    HALT_ACTION_CEILING,
    HALT_KILL_SWITCH,
    HALT_TARGET_BLOCKING,
    HALT_WINDOW_CLOSED,
    EngagementGovernor,
    get_active_governor,
    set_active_governor,
)

pytestmark = pytest.mark.asyncio


def _governor(tmp_path: Path, **policy_kwargs: object) -> EngagementGovernor:
    return EngagementGovernor(
        "eng-test",
        SafetyPolicy(**policy_kwargs),  # type: ignore[arg-type]
        outputs_root=tmp_path,
    )


# ---------------------------------------------------------------------------
# Absent by default
# ---------------------------------------------------------------------------


async def test_no_governor_is_installed_by_default() -> None:
    """The rails govern an engagement, not a process.

    Every hook is written to no-op when this returns None, which is what keeps
    the benchmark suites — which invoke methodologies directly — unchanged.
    """
    assert get_active_governor() is None


async def test_install_and_uninstall(tmp_path: Path) -> None:
    governor = _governor(tmp_path)
    set_active_governor(governor)
    try:
        assert get_active_governor() is governor
    finally:
        set_active_governor(None)
    assert get_active_governor() is None


# ---------------------------------------------------------------------------
# Rate limit + concurrency
# ---------------------------------------------------------------------------


async def test_rate_limit_paces_requests(tmp_path: Path) -> None:
    governor = _governor(tmp_path, max_requests_per_second=5.0, max_concurrent_requests=8)
    started = time.monotonic()
    # The bucket starts full (one second of burst), so the delay only begins
    # after the burst is spent — hence more requests than the burst allowance.
    for _ in range(9):
        decision = await governor.authorize("GET", "https://app.test/")
        assert decision.allowed
        governor.release()
    elapsed = time.monotonic() - started
    assert elapsed >= 0.5, f"9 requests at 5/s finished in {elapsed:.2f}s — not paced"


async def test_concurrency_cap_blocks_the_extra_request(tmp_path: Path) -> None:
    governor = _governor(tmp_path, max_requests_per_second=1000.0, max_concurrent_requests=2)
    for _ in range(2):
        assert (await governor.authorize("GET", "https://app.test/")).allowed

    third = asyncio.create_task(governor.authorize("GET", "https://app.test/"))
    await asyncio.sleep(0.05)
    assert not third.done(), "the third concurrent request was not held at the cap"

    governor.release()
    assert (await third).allowed
    governor.release()
    governor.release()


# ---------------------------------------------------------------------------
# Destructive refusal + action log
# ---------------------------------------------------------------------------


async def test_destructive_request_is_refused_and_logged(tmp_path: Path) -> None:
    governor = _governor(tmp_path, max_requests_per_second=1000.0)
    decision = await governor.authorize("POST", "https://app.test/account/change-password")

    assert not decision.allowed
    assert decision.category == "credential_change"
    assert governor.action_log.refused_count == 1
    assert governor.action_log.sent_count == 0

    records = ActionLog.read("eng-test", outputs_root=tmp_path)
    assert [r.outcome for r in records] == ["refused"]
    assert records[0].url.endswith("/account/change-password")


async def test_a_refused_request_consumes_no_slot(tmp_path: Path) -> None:
    """A refusal must be free: no rate token, no concurrency slot.

    Otherwise a target with many refused candidates would throttle the probes
    that ARE permitted.
    """
    governor = _governor(tmp_path, max_requests_per_second=1000.0, max_concurrent_requests=1)
    assert not (await governor.authorize("DELETE", "https://app.test/x")).allowed
    # The single slot must still be free.
    assert (await governor.authorize("GET", "https://app.test/")).allowed
    governor.release()


async def test_state_changing_sends_are_logged_read_only_ones_are_not(tmp_path: Path) -> None:
    governor = _governor(tmp_path, max_requests_per_second=1000.0)
    for _ in range(3):
        assert (await governor.authorize("GET", "https://app.test/page")).allowed
        governor.release()
    assert (await governor.authorize("POST", "https://app.test/comments", body="text=hi")).allowed
    governor.release()

    records = ActionLog.read("eng-test", outputs_root=tmp_path)
    assert len(records) == 1, "read-only requests must not bury the mutations"
    assert records[0].method == "POST"
    assert records[0].body_sha256


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


async def test_kill_switch_sentinel_halts_the_engagement(tmp_path: Path) -> None:
    governor = _governor(tmp_path, max_requests_per_second=1000.0)
    assert (await governor.authorize("GET", "https://app.test/")).allowed
    governor.release()

    governor.halt_path.parent.mkdir(parents=True, exist_ok=True)
    governor.halt_path.write_text("stop", encoding="utf-8")

    decision = await governor.authorize("GET", "https://app.test/")
    assert not decision.allowed
    assert governor.halted
    assert governor.halt_reason == HALT_KILL_SWITCH


async def test_the_first_halt_reason_is_the_one_kept(tmp_path: Path) -> None:
    """A later cause must not overwrite what the operator will read."""
    governor = _governor(tmp_path)
    governor.halt(HALT_KILL_SWITCH, "operator pulled the switch")
    governor.halt(HALT_TARGET_BLOCKING, "and then the WAF noticed")
    assert governor.halt_reason == HALT_KILL_SWITCH
    assert governor.halt_detail == "operator pulled the switch"


# ---------------------------------------------------------------------------
# Blocking detection
# ---------------------------------------------------------------------------


async def test_consecutive_throttling_halts(tmp_path: Path) -> None:
    governor = _governor(tmp_path, blocking_threshold=3)
    for _ in range(3):
        governor.observe_response(status=429, headers={}, body="")
    assert governor.halted
    assert governor.halt_reason == HALT_TARGET_BLOCKING


async def test_an_isolated_403_does_not_trip_blocking(tmp_path: Path) -> None:
    """The IDOR class produces 403s on purpose.

    A bare 403 is the CORRECT answer to an authorization probe. Tripping on it
    would halt every engagement that tests access control.
    """
    governor = _governor(tmp_path, blocking_threshold=3)
    for _ in range(10):
        governor.observe_response(status=403, headers={}, body="Forbidden")
        governor.observe_response(status=200, headers={}, body="ok")
    assert not governor.halted


async def test_403_with_a_waf_signature_does_trip(tmp_path: Path) -> None:
    governor = _governor(tmp_path, blocking_threshold=2)
    for _ in range(2):
        governor.observe_response(
            status=403, headers={"CF-RAY": "abc123"}, body="Attention Required"
        )
    assert governor.halted


async def test_a_clean_response_resets_the_streak(tmp_path: Path) -> None:
    governor = _governor(tmp_path, blocking_threshold=3)
    governor.observe_response(status=429, headers={}, body="")
    governor.observe_response(status=429, headers={}, body="")
    governor.observe_response(status=200, headers={}, body="ok")
    governor.observe_response(status=429, headers={}, body="")
    assert not governor.halted


async def test_halt_on_blocking_can_be_disabled(tmp_path: Path) -> None:
    governor = _governor(tmp_path, blocking_threshold=1, halt_on_blocking=False)
    governor.observe_response(status=429, headers={}, body="")
    assert not governor.halted


# ---------------------------------------------------------------------------
# Window hard stop + action ceiling
# ---------------------------------------------------------------------------


async def test_a_closed_window_halts_mid_run(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    governor = EngagementGovernor(
        "eng-test",
        SafetyPolicy(max_requests_per_second=1000.0),
        window=EngagementWindow(start=now - timedelta(hours=2), end=now - timedelta(minutes=1)),
        outputs_root=tmp_path,
    )
    decision = await governor.authorize("GET", "https://app.test/")
    assert not decision.allowed
    assert governor.halt_reason == HALT_WINDOW_CLOSED


async def test_state_change_ceiling_halts(tmp_path: Path) -> None:
    governor = _governor(tmp_path, max_requests_per_second=1000.0, max_state_changing_requests=2)
    for _ in range(2):
        assert (await governor.authorize("POST", "https://app.test/comments")).allowed
        governor.release()
    decision = await governor.authorize("POST", "https://app.test/comments")
    assert not decision.allowed
    assert governor.halt_reason == HALT_ACTION_CEILING


# ---------------------------------------------------------------------------
# Response observers
# ---------------------------------------------------------------------------


async def test_a_raising_observer_cannot_break_a_request(tmp_path: Path) -> None:
    governor = _governor(tmp_path)

    def _explode(
        status: int, headers: dict[str, str], body: str, *, session_bearing: bool = True
    ) -> None:
        raise RuntimeError("observer bug")

    seen: list[int] = []
    governor.add_response_observer(_explode)
    governor.add_response_observer(lambda s, h, b, session_bearing=True: seen.append(s))

    governor.observe_response(status=200, headers={}, body="ok")
    assert seen == [200], "a broken observer stopped a later one from running"


@pytest.mark.asyncio
async def test_the_governor_tells_observers_whether_the_session_was_carried(
    tmp_path: Path,
) -> None:
    """``session_bearing`` reaches the observer verbatim.

    Only the request seam knows whether a request carried the engagement's
    session. An observer left to infer it from the response reads the 401 of a
    deliberate anonymous control as proof the session died.
    """
    governor = _governor(tmp_path)
    seen: list[bool] = []
    governor.add_response_observer(
        lambda s, h, b, session_bearing=True: seen.append(session_bearing)
    )

    governor.observe_response(status=401, headers={}, body="", session_bearing=False)
    governor.observe_response(status=401, headers={}, body="")

    assert seen == [False, True]
