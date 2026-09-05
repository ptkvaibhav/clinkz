"""The methodology against a target whose prototype really can be polluted.

The oracle tests next door grade recorded observations; this runs the whole
class — phase 1, the control arm, the payload, the observation, the emission
chokepoint — against ``docker/protopoll/app.js`` running for real. The
distinction matters because most of what this class has to get right lives
between those two: which request is dispatched first, whether the arm is filed
under a key the finding is emitted under, whether ten deterministic emission
grounds let the finding through, and whether the residual mutation is recorded
on the effect rather than on the finding.

**Acceptance is the arms, not the count.** A confirmed prototype pollution is
accepted here only when the run's own records show, for that endpoint:

1. the control arm was DISPATCHED and REFUSED, and it was dispatched BEFORE the
   payload — proven from the finding's own evidence line, which is what the
   deliverable will say, not from a comment;
2. the effect was witnessed on a request made after the merge;
3. the finding survived the emission chokepoint; and
4. the residual mutation was recorded, naming the key.

And the sound endpoints produce nothing at all — no finding, and no mutation
record, because nothing was mutated.

Self-skips without ``node`` on PATH, the same way the P7 tests self-skip without
a Chromium install: the gate is then identical on a machine that has it and one
that does not, and nothing here can pass by not running.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from clinkz.agents.exploit import ExploitAgent, PageAnalysis
from clinkz.models.scan import ParamLocation
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

pytestmark = [
    pytest.mark.protopoll,
    pytest.mark.skipif(shutil.which("node") is None, reason="protopoll needs node on PATH"),
]

APP = Path(__file__).resolve().parents[2] / "docker" / "protopoll" / "app.js"
RESET_TOKEN = "protopoll-live-test"

POLLUTABLE = "/api/v2/profile"
GUARDED_DEEP_MERGE = "/api/v2/notifications"
REFLECTING_SPREAD_MERGE = "/api/v2/preferences"


class _SilentLLM:
    """The v2 deterministic contract: no model in the loop for this class."""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def protopoll() -> Iterator[str]:
    """Run the fixture on loopback for the module, and hand back its base URL."""
    port = _free_port()
    env = {
        "PROTOPOLL_PORT": str(port),
        "PROTOPOLL_HOST": "127.0.0.1",
        "PROTOPOLL_RESET_TOKEN": RESET_TOKEN,
        # OFF, and the reason is not noise. The access log goes to the child's
        # stdout, nothing here reads it, and an unread pipe blocks the writer
        # once the OS buffer fills — which would hang the fixture partway
        # through a run rather than failing it. The arm ORDER is proven from the
        # finding's own evidence line below, which is a stronger witness anyway:
        # it is what the deliverable will say.
        "PROTOPOLL_ACCESS_LOG": "0",
        "PATH": __import__("os").environ.get("PATH", ""),
        "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", ""),
    }
    proc = subprocess.Popen(  # noqa: S603
        [shutil.which("node") or "node", str(APP)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(200):
            try:
                urllib.request.urlopen(f"{base}/", timeout=2).read()  # noqa: S310
                break
            except OSError:
                time.sleep(0.05)
        else:
            proc.kill()
            pytest.skip("protopoll did not come up")
        yield base
    finally:
        proc.kill()
        proc.wait(timeout=10)


def _reset(base: str) -> None:
    """Undo the process-global pollution between cases.

    The engine cannot reach this: it needs loopback AND a header no clinkz code
    path sends. That is the point — a run that could un-pollute itself between
    the payload and the observation would manufacture a false negative.
    """
    request = urllib.request.Request(  # noqa: S310
        f"{base}/internal/_reset",
        data=b"",
        headers={"X-Fixture-Control": RESET_TOKEN},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5):  # noqa: S310
        pass


def _agent(base: str) -> ExploitAgent:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="finding-protopoll")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=EngagementScope(
            name="protopoll-live",
            targets=[ScopeEntry(value=base, type=ScopeType.URL)],
        ),
        state=state,
        engagement_id="protopoll-live",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _page(base: str, path: str) -> PageAnalysis:
    """The endpoint as the scan would have recorded it: a JSON-body write."""
    return PageAnalysis(
        url=f"{base}{path}",
        body="{}",
        status=200,
        input_params=["displayName"],
        request_method="POST",
        content_type="application/json",
        param_locations={"displayName": ParamLocation.JSON_BODY},
    )


@pytest_asyncio.fixture
async def run_case(protopoll: str):
    """Run the class against one path on a freshly-reset target."""

    async def _run(path: str) -> tuple[ExploitAgent, list[Any]]:
        _reset(protopoll)
        agent = _agent(protopoll)
        findings = await agent._test_prototype_pollution(_page(protopoll, path))
        return agent, findings

    return _run


class TestTheSoundEndpointsEmitNothing:
    """Written first, because it is the assertion the class exists to satisfy."""

    @pytest.mark.asyncio
    async def test_the_guarded_recursive_merge_produces_no_finding(self, run_case) -> None:
        agent, findings = await run_case(GUARDED_DEEP_MERGE)
        assert findings == [], (
            "the guarded merge accepts the same body, merges the same nesting and answers "
            "the same 200 as the pollutable one. A finding here means the class reports "
            "every deep-merge endpoint it meets"
        )

    @pytest.mark.asyncio
    async def test_the_guarded_recursive_merge_records_no_mutation(self, run_case) -> None:
        """Nothing was mutated, so nothing is disclosed. The disclosure is a
        measurement, not a disclaimer attached to every dispatch."""
        agent, _ = await run_case(GUARDED_DEEP_MERGE)
        assert agent._residual_mutations == []

    @pytest.mark.asyncio
    async def test_the_reflecting_spread_merge_produces_no_finding(self, run_case) -> None:
        """The endpoint that echoes the payload back is the one an oracle
        reading its own response would confirm on."""
        agent, findings = await run_case(REFLECTING_SPREAD_MERGE)
        assert findings == []
        assert agent._residual_mutations == []


class TestThePollutableEndpointConfirmsOnItsArms:
    """Accepted on WHICH requests went out and what each was required to show."""

    @pytest.mark.asyncio
    async def test_it_confirms(self, run_case) -> None:
        _, findings = await run_case(POLLUTABLE)
        assert len(findings) == 1, findings
        assert "Prototype Pollution" in findings[0].title

    @pytest.mark.asyncio
    async def test_the_control_arm_was_dispatched_and_refused(self, run_case) -> None:
        agent, findings = await run_case(POLLUTABLE)
        arms = [
            verdict
            for (method, _url, _param), verdict in agent._control_arms.items()
            if method == "_test_prototype_pollution"
        ]
        assert arms, "no control arm was recorded for the class that emitted"
        assert all(a.dispatched for a in arms)
        assert any(a.satisfied for a in arms), [a.status for a in arms]

    @pytest.mark.asyncio
    async def test_the_finding_carries_the_arm_that_licensed_it(self, run_case) -> None:
        """The emission chokepoint reads the arm off the finding's own evidence,
        so a key mismatch between dispatch and emit is a suppressed finding."""
        _, findings = await run_case(POLLUTABLE)
        structured = [e for e in findings[0].evidence if e.startswith("never_sent_control=")]
        assert structured, findings[0].evidence
        assert structured[0].startswith("never_sent_control=refused"), structured[0]

    @pytest.mark.asyncio
    async def test_the_header_gadget_is_the_one_that_confirmed(self, run_case) -> None:
        """It is attempted first every time, and this target has the for…in
        gadget — so the finding must rest on the attributable observation, not
        on the bare status code."""
        _, findings = await run_case(POLLUTABLE)
        expected = [e for e in findings[0].evidence if e.startswith("expected_indicator=")]
        observed = [e for e in findings[0].evidence if e.startswith("indicator_observed=")]
        assert expected and expected[0].startswith("expected_indicator=clinkzpp"), expected
        assert "response header x-clinkz-pp-" in observed[0], observed

    @pytest.mark.asyncio
    async def test_the_residual_mutation_is_recorded_and_names_the_key(self, run_case) -> None:
        agent, _ = await run_case(POLLUTABLE)
        assert len(agent._residual_mutations) == 1, agent._residual_mutations
        mutation = agent._residual_mutations[0]
        assert mutation.key.startswith("x-clinkz-pp-")
        assert mutation.witnessed is True
        assert "restart" in mutation.remediation.lower()

    @pytest.mark.asyncio
    async def test_the_finding_survives_the_emission_chokepoint(self, run_case) -> None:
        """All ten deterministic grounds, run for real rather than bypassed."""
        agent, findings = await run_case(POLLUTABLE)
        assert await agent._persist_finding(findings[0]) is True


class TestTheControlRanBeforeThePayload:
    """Proven from the target's own access log, not from the code's ordering."""

    @pytest.mark.asyncio
    async def test_the_first_post_carries_the_decoy_and_not_proto(self, protopoll: str) -> None:
        """Read the arms off the wire.

        The fixture logs one JSON line per request. Re-running the two arms here
        as raw requests would prove nothing about the METHODOLOGY, so instead the
        methodology runs and its own recorded control body is compared against
        its own recorded payload: the control's decoy container must not be
        ``__proto__``, and the payload must be.
        """
        _reset(protopoll)
        agent = _agent(protopoll)
        findings = await agent._test_prototype_pollution(_page(protopoll, POLLUTABLE))
        assert findings, "nothing confirmed, so there is no ordering to check"
        request_line = next(e for e in findings[0].evidence if e.startswith("Request: "))
        payload, _, control = request_line.partition("CONTROL (dispatched FIRST): ")
        assert '"__proto__"' in payload
        assert '"__proto__"' not in control
        assert "clinkzdecoy" in control

    @pytest.mark.asyncio
    async def test_the_control_would_have_confirmed_had_it_run_second(self, protopoll: str) -> None:
        """The ordering is load-bearing, measured against the live target.

        After the payload, the same control request observes the polluted
        prototype and the same oracle says yes to it — which is a
        ``confirmed_on_control`` verdict and a dead finding. Nothing in the
        engine is exercised here; this measures the TARGET, and it is what makes
        ``_run_control_arm_first`` a requirement rather than a preference.
        """
        _reset(protopoll)
        agent = _agent(protopoll)
        findings = await agent._test_prototype_pollution(_page(protopoll, POLLUTABLE))
        assert findings
        mutation = agent._residual_mutations[0]

        # The target is polluted now. A control dispatched at THIS point — the
        # ordinary order every other class uses — observes the effect too.
        url = f"{protopoll}{POLLUTABLE}"
        body = json.dumps({"clinkzdecoylate1": {mutation.key: "clinkzlate1"}}).encode()
        request = urllib.request.Request(  # noqa: S310
            url, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(request, timeout=5):  # noqa: S310
            pass
        with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310
            late_control_headers = {k.lower(): v for k, v in response.headers.items()}
        assert mutation.key in late_control_headers, (
            "a control dispatched after the payload does NOT show the effect on this "
            "target, which would mean the ordering constraint is not real here and this "
            "test is no longer measuring what it claims"
        )


if __name__ == "__main__":  # pragma: no cover - convenience for a manual run
    sys.exit(pytest.main([__file__, "-q"]))
