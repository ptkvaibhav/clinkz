#!/usr/bin/env python3
"""Drive the REAL auth path against a live target, and print the transcript.

The whole point of an adaptive layer is that it does something the deterministic
one cannot, and there is exactly one way to find out whether it does: point it at
an application whose login the parser genuinely cannot read, and look at what it
proposed and what came back.

**The login URL is not handed in.** ``detect_auth_mechanism`` runs for real, so
the discovery gap this project has been bitten by before — a direct auth check
that supplies the login URL and thereby hides the fact that nothing could find it
— is not reintroduced here. What this driver skips is recon, scan, research,
exploit and report; what it does NOT skip is any part of the authentication path.

It is a diagnostic, not a gate. It sends real credentials to a real target, so it
runs only against a target an operator has authorised, and it installs the same
governor a full engagement installs: the per-account budget, the rate limit and
the action log all apply, and the run refuses exactly what an engagement would.

Usage::

    python scripts/live_adaptive_auth_validation.py \\
        --target http://calcom-real:3000 \\
        --username someone@example.com --password '...' \\
        [--role admin] [--exec-mode docker|local] [--json]

Exit codes: ``0`` a session was seated (by either layer), ``1`` neither layer
seated one — which is a RESULT, and the transcript says why — ``2`` bad input.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import pathlib
import sys
from typing import Any
from urllib.parse import urlparse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Base URL of the target.")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--role", default="admin")
    parser.add_argument("--privilege", type=int, default=0)
    parser.add_argument("--exec-mode", default="docker", choices=("docker", "local"))
    parser.add_argument(
        "--login-url",
        default="",
        help=(
            "Operator declaration, passed through as RoleCredential.login_url. "
            "OMIT IT to exercise discovery, which is the interesting case."
        ),
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser.parse_args()


async def _run(args: argparse.Namespace) -> int:
    # The execution mode has to be set before anything imports the settings
    # object, which is why this is here rather than at module scope.
    os.environ["TOOL_EXEC_MODE"] = args.exec_mode

    from clinkz.engagement.auth_state import detect_auth_mechanism
    from clinkz.engagement.secrets import register_credential_set
    from clinkz.models.engagement import CredentialSet, RoleCredential, SafetyPolicy
    from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
    from clinkz.orchestrator.orchestrator import OrchestratorAgent, _ToolHttpProbe
    from clinkz.safety.governor import EngagementGovernor, set_active_governor

    parsed = urlparse(args.target)
    if not parsed.scheme or not parsed.hostname:
        print(f"--target must be an absolute URL, got {args.target!r}")
        return 2

    engagement_id = "adaptive-auth-live"
    scope = EngagementScope(
        name=engagement_id,
        targets=[ScopeEntry(value=args.target, type=ScopeType.URL)],
    )
    credentials = CredentialSet(
        credentials=[
            RoleCredential(
                role=args.role,
                username=args.username,
                password=args.password,
                privilege=args.privilege,
                login_url=args.login_url,
            )
        ]
    )

    # REGISTER THE SECRET, exactly as ``load_credentials`` does for a credential
    # file. A driver that assembles a CredentialSet in code gets no registration,
    # and every artifact the run writes then carries the plaintext: this driver
    # left ``"password": "pro"`` in 28 lines of its own ``actions.jsonl`` before
    # this line existed, because the action log's body excerpt is redacted by
    # VALUE and no value had been registered. The engine's redaction reaches only
    # where the engine was told what to redact.
    register_credential_set(credentials)

    # The same rails a real engagement installs. Without them the per-account
    # budget would be absent and the loop would be exercised under conditions no
    # engagement ever runs under, which is the opposite of a live validation.
    governor = EngagementGovernor(engagement_id, SafetyPolicy())
    set_active_governor(governor)

    agent = OrchestratorAgent.__new__(OrchestratorAgent)
    agent._scope = scope
    agent._engagement_id = engagement_id
    agent._credentials = credentials
    agent._role_sessions = {}
    agent._auth_transcripts = []
    agent._session_material_source = ""
    agent._proven_login = None
    agent._reauth_credential = None
    agent._reauth_login_url = ""
    agent._recon_component_labels = []
    agent._package_identity_coverage_note = ""
    agent._primary_target_url = lambda: args.target
    agent._logger = __import__("logging").getLogger("adaptive-auth-live")

    from clinkz.llm.factory import get_llm_client

    agent._llm = get_llm_client(agent_role="orchestrator")

    probe = _ToolHttpProbe(scope, engagement_id)
    detection = await detect_auth_mechanism(probe, args.target.rstrip("/"))
    print(f"Detected mechanism : {detection.mechanism.value}")
    print(f"Detected login URL : {detection.login_url or '(none)'}")
    for line in detection.evidence:
        print(f"  evidence: {line}")
    print(f"  probed {len(detection.probed)} candidate(s)")
    print()

    cred = credentials.authenticating[0]
    await agent._authenticate_role(cred, detection.login_url or args.target)

    session = agent._role_sessions.get(cred.role, {})
    transcript = agent._auth_transcripts[0] if agent._auth_transcripts else None

    if args.as_json:
        print(
            json.dumps(
                {
                    "mechanism": detection.mechanism.value,
                    "detected_login_url": detection.login_url,
                    "established": bool(session.get("established")),
                    "seated_by": session.get("seated_by", "deterministic"),
                    "transcript": transcript.redacted() if transcript else None,
                    "governor": _governor_view(governor.stats()),
                },
                indent=2,
            )
        )
    else:
        print("=" * 72)
        print("DETERMINISTIC PASS")
        print("=" * 72)
        for observation in session.get("observations") or []:
            print(f"  - {observation}")
        print(f"  posted to      : {session.get('posted_to') or '(nothing dispatched)'}")
        print(f"  login verdict  : {session.get('login_verdict', '?')}")
        print(f"  verdict says   : {session.get('login_verdict_evidence', '')}")
        print()
        print("=" * 72)
        print("ADAPTIVE LAYER")
        print("=" * 72)
        if transcript is None:
            print("  (no transcript — the pass did not reach the layer)")
        else:
            for line in transcript.render_lines():
                print(f"  {line.lstrip('- ')}")
            for attempt in transcript.attempts:
                if attempt.proposal.rationale:
                    print(f"      turn {attempt.turn} reasoning: {attempt.proposal.rationale}")
        print()
        stats = governor.stats()
        print(f"Credential attempts : {stats.get('credential_attempts')}")
        print(f"Credential stops    : {stats.get('credential_stops')}")
        print(f"Requests authorized : {stats.get('requests_authorized')}")
        print()
        print(
            f"RESULT: established={bool(session.get('established'))} "
            f"seated_by={session.get('seated_by', 'deterministic')}"
        )

    return 0 if session.get("established") else 1


def _governor_view(stats: dict[str, Any]) -> dict[str, Any]:
    """The counters this driver reports. A view, never a second population."""
    return {
        key: stats.get(key)
        for key in (
            "requests_authorized",
            "credential_attempts",
            "credential_stops",
            "state_changing_sent",
            "state_changing_refused",
            "halted",
            "halt_reason",
        )
    }


def main() -> int:
    args = _parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
