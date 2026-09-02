#!/usr/bin/env python3
"""Offline re-grade of stored IDOR findings against the ANCHORED four-arm oracle.

**Sends nothing.** It reads a stored bundle's ``trace.jsonl`` and
``tool_invocations/`` — the requests the run actually made and the bytes that
came back — and replays them through
:mod:`clinkz.agents._idor_oracle` as it stands now.

**Why a re-grade and not a re-run.** A re-run measures the target as it is
today; the question here is whether the REASONING that produced a stored
finding survives the corrected oracle. Those are different questions and only
the second is about this engine. The 2026-08-31 Juice Shop envelope is the case
in point: every one of its five IDOR findings sat on a target-confirmed
scoreboard solve, and the arms were nevertheless inverted.

**What a stored bundle cannot answer, and why that is a verdict of its own.**
The corrected oracle asks for arms the old one never dispatched. Anchoring
``ref(A)`` re-points the crossing arm at a DIFFERENT reference, and the
anonymous and owner-read arms for that reference may simply not be in the
corpus. An arm that was never sent refused nothing — the same rule
:class:`~clinkz.agents._control_arm.ControlVerdict` applies everywhere else — so
the honest outcome is ``REDISPATCH_REQUIRED``, held apart from both SURVIVES and
REFUTED. Reporting it as a pass would be the acceptance-criterion mistake this
whole change is about; reporting it as a failure would claim a measurement
nobody made.

Usage::

    python scripts/regrade_idor_arms.py <engagement-id> [--outputs-root DIR] [--json]

Exit codes: 0 the re-grade ran · 2 the bundle could not be read.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from dataclasses import dataclass, field
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from clinkz.agents._idor_oracle import (  # noqa: E402
    ArmObservation,
    IDORArm,
    SelfAnchor,
    anchor_self_reference,
    decide_idor,
    owner_claim,
)
from clinkz.agents._principal import ANONYMOUS  # noqa: E402

#: A verdict this replay can reach. Kept apart because they call for opposite
#: follow-up: a REFUTED finding is removed, a REDISPATCH_REQUIRED one is
#: re-measured against the live target.
SURVIVES = "SURVIVES"
REFUTED = "REFUTED"
REDISPATCH_REQUIRED = "REDISPATCH_REQUIRED"


@dataclass
class Exchange:
    """One recorded HTTP exchange, as the bundle stored it."""

    seq: int
    ts: str
    url: str
    status: int
    body: str
    #: Fingerprint of the bearer token this request carried, from the REDACTED
    #: header the bundle stores. The value is gone; the fingerprint still tells
    #: two principals apart, which is all this replay needs.
    token_fp: str
    has_auth: bool


@dataclass
class Case:
    """One stored IDOR verification, re-graded."""

    endpoint: str
    parameter: str
    #: What the stored run's ``crossing`` arm carried — which on the run this
    #: script exists for was the CALLER's own record.
    recorded_reference: str
    #: What its ``self`` arm carried: the crawl's value, under whichever session
    #: was crawling.
    recorded_self_reference: str
    #: The never-issued reference its control arm carried. Re-used verbatim: it
    #: was minted in the same shape and remains a reference nobody owns.
    recorded_absent_reference: str
    recorded_confirmed: bool
    recorded_attribution: str
    anchor: SelfAnchor = field(default_factory=lambda: SelfAnchor(anchored=False))
    crossing_reference: str = ""
    verdict: str = ""
    why: str = ""
    missing_arms: tuple[str, ...] = ()

    def row(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "recorded_self_reference": self.recorded_self_reference,
            "recorded_reference": self.recorded_reference,
            "recorded_attribution": self.recorded_attribution,
            "anchored_reference": self.anchor.reference,
            "crossing_reference": self.crossing_reference,
            "verdict": self.verdict,
            "why": self.why,
            "missing_arms": list(self.missing_arms),
        }


_STATUS_RE = re.compile(r"^HTTP/[\d.]+ (\d{3})", re.M)
_TIMING_RE = re.compile(r"\n?__CURL_TIMING__[\d.]+\n?$")
_TOKEN_FP_RE = re.compile(r"sha256=([0-9a-f]+)")


def load_exchanges(bundle: pathlib.Path) -> list[Exchange]:
    """Every recorded ``http_client`` invocation, parsed.

    The bundle stores the argv and the raw stdout, so the request's URL and the
    response's status and body are all recoverable. The Authorization header is
    already redacted to a fingerprint by the engine's own writer — which is
    exactly enough to tell one principal's arm from another's without the
    replay ever holding a live token.
    """
    out: list[Exchange] = []
    for path in sorted((bundle / "tool_invocations").glob("*_http_client.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        cmd = raw.get("command")
        if isinstance(cmd, str):
            try:
                cmd = json.loads(cmd)
            except ValueError:
                cmd = [cmd]
        if not isinstance(cmd, list):
            continue
        argv = [str(a) for a in cmd]
        url = next((a for a in argv if a.startswith(("http://", "https://"))), "")
        auth = next((a for a in argv if a.lower().startswith("authorization:")), "")
        stdout = raw.get("stdout") or ""
        statuses = _STATUS_RE.findall(stdout)
        body = stdout.split("\r\n\r\n")[-1] if "\r\n\r\n" in stdout else stdout
        fp = _TOKEN_FP_RE.search(auth)
        out.append(
            Exchange(
                seq=int(raw.get("seq") or 0),
                ts=str(raw.get("ts") or ""),
                url=url,
                status=int(statuses[-1]) if statuses else 0,
                body=_TIMING_RE.sub("", body),
                token_fp=fp.group(1) if fp else "",
                has_auth=bool(auth),
            )
        )
    return out


def load_idor_cases(bundle: pathlib.Path) -> list[Case]:
    """The confirmed IDOR verifications the stored trace recorded.

    Paired with the ``never_sent_control`` event that precedes each one, which
    is the only place the trace carries the ENDPOINT the arms were dispatched
    against — the verification event carries only the parameter.
    """
    cases: list[Case] = []
    pending: dict[str, tuple[str, str]] = {}
    trace = bundle / "trace.jsonl"
    if not trace.is_file():
        return cases
    for line in trace.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        payload = event.get("payload") or {}
        if payload.get("skill") != "idor":
            continue
        if payload.get("phase_name") == "never_sent_control":
            pending[str(payload.get("decoy") or "")] = (
                str(payload.get("endpoint") or ""),
                str(payload.get("parameter") or ""),
            )
        if payload.get("phase_name") != "verification" or not payload.get("verified"):
            continue
        arms = payload.get("arms") or []
        decoy = _arm_reference(arms, IDORArm.NONEXISTENT)
        endpoint, parameter = pending.get(decoy, ("", str(payload.get("param") or "")))
        cases.append(
            Case(
                endpoint=endpoint,
                parameter=parameter,
                recorded_reference=_arm_reference(arms, IDORArm.CROSSING),
                recorded_self_reference=_arm_reference(arms, IDORArm.SELF),
                recorded_absent_reference=decoy,
                recorded_confirmed=True,
                recorded_attribution=str(payload.get("attribution") or ""),
            )
        )
    return cases


def _arm_reference(arms: list[str], arm: IDORArm) -> str:
    """The reference one recorded arm line says it carried."""
    for line in arms:
        if line.startswith(f"{arm.value}:"):
            match = re.search(r"ref='([^']*)'", line)
            return match.group(1) if match else ""
    return ""


def _resource_path(endpoint: str, reference: str) -> str:
    """The path the arms actually dispatched, with the placeholder resolved.

    The endpoint is stored with the discoverer's placeholder
    (``/rest/basket/:id``, ``/rest/basket/:p3`` — two spellings of one route),
    and matching on it would miss every exchange. The DISPATCHED path is what
    the corpus holds, so that is what is looked up.
    """
    return re.sub(r":[A-Za-z_][A-Za-z0-9_]*", reference, endpoint)


def find_exchange(
    exchanges: list[Exchange],
    endpoint: str,
    reference: str,
    *,
    token_fp: str | None,
) -> Exchange | None:
    """The recorded exchange for one arm, or ``None`` when it was never sent.

    ``token_fp=None`` asks for the anonymous arm — a request that carried no
    Authorization header at all, which is what the anonymous arm IS.
    """
    want = _resource_path(endpoint, reference)
    for exchange in exchanges:
        if not exchange.url.endswith(want):
            continue
        if token_fp is None and not exchange.has_auth:
            return exchange
        if token_fp is not None and exchange.token_fp == token_fp:
            return exchange
    return None


def _obs(
    arm: IDORArm,
    exchange: Exchange | None,
    reference: str,
    principal: str,
) -> ArmObservation:
    if exchange is None:
        return ArmObservation(
            arm=arm,
            dispatched=False,
            status=0,
            body="",
            reference=reference,
            principal=principal,
        )
    return ArmObservation(
        arm=arm,
        dispatched=True,
        status=exchange.status,
        body=exchange.body,
        reference=reference,
        principal=principal,
    )


def regrade(
    case: Case,
    exchanges: list[Exchange],
    *,
    caller_fp: str,
    owner_fp: str,
    caller_identity: frozenset[str],
    held_identities: dict[str, frozenset[str]],
    caller_label: str,
    owner_label: str,
    numeric_span: int = 8,
) -> Case:
    """Re-grade one stored case through the anchored oracle."""
    # 1. Anchor: every reference the corpus shows the CALLER being served, in
    #    the order the anchor sweep would have tried them.
    candidates: list[tuple[str, str]] = []
    for reference in _candidate_references(case, numeric_span):
        exchange = find_exchange(exchanges, case.endpoint, reference, token_fp=caller_fp)
        if exchange is not None and exchange.status in (200, 201, 202, 206) and exchange.body:
            candidates.append((reference, exchange.body))
    case.anchor = anchor_self_reference(
        candidates=tuple(candidates), caller_identity=caller_identity
    )
    if not case.anchor.anchored:
        case.verdict = REFUTED
        case.why = case.anchor.why
        return case

    # 2. The crossing is now a DIFFERENT reference: the nearest one the caller
    #    does not own. That is the whole correction.
    crossing_reference = next(
        (reference for reference, _body in candidates if reference != case.anchor.reference),
        "",
    )
    if not crossing_reference:
        case.verdict = REDISPATCH_REQUIRED
        case.why = "no reference other than the caller's own was recorded for this endpoint"
        case.missing_arms = ("crossing",)
        return case
    case.crossing_reference = crossing_reference

    self_ex = find_exchange(exchanges, case.endpoint, case.anchor.reference, token_fp=caller_fp)
    crossing_ex = find_exchange(exchanges, case.endpoint, crossing_reference, token_fp=caller_fp)
    anon_ex = find_exchange(exchanges, case.endpoint, crossing_reference, token_fp=None)
    owner_ex = find_exchange(exchanges, case.endpoint, crossing_reference, token_fp=owner_fp)
    absent_ex = find_exchange(
        exchanges, case.endpoint, case.recorded_absent_reference, token_fp=caller_fp
    )

    missing = [
        name
        for name, ex in (
            ("anonymous", anon_ex),
            ("owner_read", owner_ex),
            ("nonexistent", absent_ex),
        )
        if ex is None
    ]

    verdict = decide_idor(
        self_arm=_obs(IDORArm.SELF, self_ex, case.anchor.reference, caller_label),
        crossing=_obs(IDORArm.CROSSING, crossing_ex, crossing_reference, caller_label),
        nonexistent=_obs(
            IDORArm.NONEXISTENT, absent_ex, case.recorded_absent_reference, caller_label
        ),
        anonymous=_obs(IDORArm.ANONYMOUS, anon_ex, crossing_reference, ANONYMOUS),
        owner_read=_obs(IDORArm.OWNER_READ, owner_ex, crossing_reference, owner_label),
        anchor=case.anchor,
        caller_identity=caller_identity,
        held_identities=held_identities,
        principals_available=2,
        principals_required=2,
        single_role_why="single_role_cannot_attribute",
        privilege_order_known=True,
    )
    case.missing_arms = tuple(missing)
    case.why = verdict.detail
    if verdict.confirmed:
        case.verdict = SURVIVES
    elif missing:
        # A refusal that turns on an arm the bundle does not hold is not a
        # refusal, it is an unanswered question. Which it is, is decided by
        # whether the OBJECT still names an owner: that half is answerable
        # offline and is the substantive claim.
        claim = owner_claim(
            crossing_body=(crossing_ex.body if crossing_ex else ""),
            self_body=(self_ex.body if self_ex else ""),
            caller_identity=caller_identity,
            held_identities=held_identities,
        )
        case.verdict = REDISPATCH_REQUIRED if claim is not None else REFUTED
        if claim is not None:
            case.why = (
                f"the anchored crossing names an owner other than the caller "
                f"({claim.route} on {claim.field}), and the arms this oracle needs to "
                f"complete the grade were never dispatched against "
                f"{crossing_reference!r}: {', '.join(missing)}"
            )
    else:
        case.verdict = REFUTED
    return case


def _candidate_references(case: Case, span: int) -> list[str]:
    """References worth looking for, mirroring the agent's anchor sweep.

    Wider than the live sweep on purpose: the live one stops at the first
    reference that names the caller because every further probe is a request
    against a client's target, and this one sends nothing. What it may NOT do is
    invent an exchange — a reference the corpus does not hold simply is not
    found, which is what produces ``REDISPATCH_REQUIRED``.
    """
    seen: list[str] = []
    for value in (case.recorded_self_reference, case.recorded_reference):
        if value and value not in seen:
            seen.append(value)
    for value in list(seen):
        try:
            base = int(value)
        except ValueError:
            continue
        for delta in range(-span, span + 1):
            stepped = base + delta
            if stepped > 0 and str(stepped) not in seen:
                seen.append(str(stepped))
    return seen


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engagement")
    parser.add_argument("--outputs-root", default="outputs")
    parser.add_argument("--caller-token-fp", required=True, help="bearer fingerprint of A")
    parser.add_argument("--owner-token-fp", required=True, help="bearer fingerprint of B")
    parser.add_argument("--caller-identity", required=True, help="comma-separated identity values")
    parser.add_argument("--owner-identity", required=True, help="comma-separated identity values")
    parser.add_argument("--caller-label", default="A")
    parser.add_argument("--owner-label", default="B")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    bundle = pathlib.Path(args.outputs_root) / args.engagement
    if not bundle.is_dir():
        print(f"no such bundle: {bundle}", file=sys.stderr)
        return 2

    exchanges = load_exchanges(bundle)
    cases = load_idor_cases(bundle)
    if not exchanges:
        print(f"{bundle} holds no recorded http_client invocations", file=sys.stderr)
        return 2

    caller_identity = frozenset(v.strip() for v in args.caller_identity.split(",") if v.strip())
    owner_identity = frozenset(v.strip() for v in args.owner_identity.split(",") if v.strip())

    rows = []
    for case in cases:
        rows.append(
            regrade(
                case,
                exchanges,
                caller_fp=args.caller_token_fp,
                owner_fp=args.owner_token_fp,
                caller_identity=caller_identity,
                held_identities={args.owner_label: owner_identity},
                caller_label=args.caller_label,
                owner_label=args.owner_label,
            ).row()
        )

    if args.json:
        print(json.dumps({"engagement": args.engagement, "cases": rows}, indent=2))
        return 0

    print(f"IDOR re-grade — {args.engagement}   ({len(rows)} stored confirmations)")
    print()
    for row in rows:
        print(f"  {row['verdict']:<20} {row['endpoint']}  param={row['parameter']}")
        print(
            f"      recorded: self={row['recorded_self_reference']!r} "
            f"crossing={row['recorded_reference']!r} "
            f"attribution={row['recorded_attribution']}"
        )
        print(
            f"      anchored: ref(A)={row['anchored_reference']!r} "
            f"ref(B)={row['crossing_reference']!r}"
        )
        if row["missing_arms"]:
            print(f"      arms never dispatched: {', '.join(row['missing_arms'])}")
        print(f"      {row['why']}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
