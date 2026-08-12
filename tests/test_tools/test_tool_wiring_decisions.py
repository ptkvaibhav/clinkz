"""Which tools are wired, which are not, and why — pinned so it cannot drift.

Three capabilities now RESOLVE that previously could not (``httpx`` and
``nikto`` did not declare the chain capability they were listed under, and
``subdomain_discovery`` was declared by nothing at all). Resolving is not the
same as being used, and for three of them the honest answer is that no agent
should ask.

The standing rule is that **third-party tool output is a LEAD or a hypothesis
for our own oracles to confirm, never an emitted finding on the tool's say-so.**
Wiring a tool whose entire output is verdicts we cannot confirm does not add
coverage — it adds leads an operator has to triage, and a worklist of
unconfirmable leads is the same disservice as a report of unconfirmed findings,
one field rename away.

So each unwired tool carries a reason here, as a test, because a reason in a
commit message is invisible six months later and a reason in a docstring drifts.
If someone wires one of these, this file is what they have to change, and
changing it means writing down what changed about the answer.
"""

from __future__ import annotations

import pytest

from clinkz.tools.resolver import TOOL_CHAINS, ToolResolver

#: Capabilities an agent genuinely requests today, and where.
WIRED: dict[str, str] = {
    "web_fingerprinting": "ReconAgent._step_web_recon — the component inventory",
    "port_scanning": "ReconAgent._step_port_scan",
    "service_detection": "ReconAgent._step_service_scan — the versioned component source",
    "waf_detection": "ReconAgent._step_web_recon",
    "web_crawling": "ScanAgent — surface discovery, through the declared contract",
    "directory_fuzzing": "ScanAgent — surface discovery, through the declared contract",
    "http_request": "every methodology probe, the single HTTP chokepoint",
    "sql_injection_testing": "ExploitAgent._run_sqlmap — recorded as a LEAD, never a finding",
    "client_side_execution": "ExploitAgent P7 — the client-side execution oracle",
}

#: Capabilities that resolve but that no agent requests, each with the reason.
#: A tool here is not broken and not forgotten; it is a decision.
DELIBERATELY_UNWIRED: dict[str, str] = {
    "vulnerability_scanning": (
        "nuclei and nikto emit VERDICTS — 'template X matched', 'server discloses Y' — "
        "and under the standing rule a third-party verdict is a lead requiring one of our "
        "own oracles to confirm. For nuclei the confirmable subset is version/banner "
        "matching, which is exactly what knowledge/component_cves.py now does with an "
        "explicit affected-range predicate and an explicit oracle-or-lead outcome; feeding "
        "the same question in through a template engine would add a much noisier input to "
        "a path that already answers it honestly. For nikto, the header half is already "
        "covered by _test_security_headers observing the response ourselves, and the "
        "'interesting file found' half is directory discovery, which ffuf and katana "
        "already contribute through the declared discovery contract. Wiring either would "
        "add unconfirmable leads and no capability."
    ),
    "subdomain_discovery": (
        "subfinder expands the TARGET SET, and the target set is the authorization "
        "boundary. A subdomain it discovers is not covered by the engagement's "
        "AuthorizationRecord, so acting on one would be testing a host the client did not "
        "authorise — the single thing engagement/gate.py exists to prevent. Wiring it "
        "would mean either silently widening scope (never) or producing a list of hosts we "
        "then refuse to touch (a lead about scope, not about a vulnerability). It stays "
        "unwired until there is an operator-facing flow that takes discovered subdomains "
        "back through authorization."
    ),
}


@pytest.fixture(scope="module")
def resolver() -> ToolResolver:
    return ToolResolver()


def test_every_chained_capability_is_either_wired_or_reasoned() -> None:
    """No capability may be merely present.

    A capability that resolves, is used by nobody, and has no stated reason is
    indistinguishable from one that was wired and then silently stopped being
    called — which is the shape of every defect the contribution ledger exists
    to catch.
    """
    accounted = set(WIRED) | set(DELIBERATELY_UNWIRED)
    unaccounted = sorted(set(TOOL_CHAINS) - accounted)
    assert not unaccounted, (
        f"these capabilities have a declared chain but neither a caller nor a reason: {unaccounted}"
    )


def test_no_capability_is_both_wired_and_unwired() -> None:
    assert not (set(WIRED) & set(DELIBERATELY_UNWIRED))


@pytest.mark.parametrize("capability", sorted(DELIBERATELY_UNWIRED))
def test_an_unwired_capability_states_a_substantive_reason(capability: str) -> None:
    """A one-word reason is an omission wearing a decision's clothes."""
    reason = DELIBERATELY_UNWIRED[capability]
    assert len(reason) > 200, f"{capability}'s reason is too thin to be a decision"


@pytest.mark.parametrize("capability", sorted(DELIBERATELY_UNWIRED))
def test_an_unwired_capability_is_genuinely_uncalled(capability: str) -> None:
    """The reason has to match reality, or it is documentation of a wish.

    Searched over the source rather than asserted, so wiring one of these without
    updating this file fails here.
    """
    from pathlib import Path

    src = Path(__file__).resolve().parents[2] / "src" / "clinkz"
    callers = [
        path.name
        for path in src.rglob("*.py")
        if f'find_tool("{capability}")' in path.read_text(encoding="utf-8")
        or f'find_tools_ranked("{capability}")' in path.read_text(encoding="utf-8")
        or f'try_until_sufficient(\n            "{capability}"' in path.read_text(encoding="utf-8")
    ]
    # The tool wrapper's own docstring may name its capability; a CALLER is what
    # this is about, so the wrapper module itself does not count.
    callers = [name for name in callers if name not in ("subfinder.py", "nikto.py", "nuclei.py")]
    assert not callers, (
        f"'{capability}' is listed as deliberately unwired but is requested by {callers}. "
        f"Either remove it from DELIBERATELY_UNWIRED or explain the new flow."
    )


@pytest.mark.parametrize("capability", sorted(WIRED))
def test_a_wired_capability_resolves_to_a_shipped_tool(
    resolver: ToolResolver, capability: str
) -> None:
    """A caller asking for a capability nothing implements gets ``None`` forever."""
    assert resolver._capability_map.get(capability), (
        f"'{capability}' is wired to {WIRED[capability]} but no wrapper declares it"
    )
