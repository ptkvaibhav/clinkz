"""One authenticated Juice Shop engagement, graded by the target itself.

Juice Shop marks a challenge solved only when it is genuinely exploited and
exposes that state at ``/api/Challenges``, which makes the target the grader
rather than us. This harness runs the engagement between two scoreboard
snapshots and reconciles **two independent numbers that must not be conflated**:

  * **challenges solved** — what the target confirmed we did to it;
  * **findings emitted** — what the engagement reported.

Every mismatch means something different and none may be assumed away:

  * *solved but not reported* — a real vulnerability was exercised and nothing
    was emitted. A reporting gap, exactly as serious as the reverse.
  * *reported but not solved* — either a genuine finding **outside the challenge
    set** (Juice Shop's challenge list is not a complete vulnerability
    inventory) or a phantom. Which one it is has to be reasoned from the
    finding's own evidence, and this harness prints that evidence rather than
    guessing.

**The addressable denominator is DERIVED, not inherited.** A challenge is
addressable when its own category maps to a vulnerability class this engine
actually dispatches AND its difficulty is 3 or below — the point past which
Juice Shop's challenges turn into multi-step puzzles requiring domain knowledge
or out-of-band information rather than a reachable vulnerability. Both halves of
that rule are stated here and computed from the live target, so the number is
auditable. It is deliberately **not** forced to match any previously-quoted
figure.

Usage::

    python scripts/juiceshop_benchmark_run.py \\
        --authorization <auth.json> --benchmark-profile <bp.json> --creds <creds.json>
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _artifact_io import write_redacted_json, write_redacted_text  # noqa: E402
from d1_consistency_runner import (  # noqa: E402
    OUTPUTS,
    newest_engagement_dirs,
    read_artifact_scan,
    read_report,
)

BASE = "http://localhost:3000"
COMPOSE = ["docker", "compose", "-f", "docker/docker-compose.yml"]
RESULTS_DIR = Path("outputs/_juiceshop_benchmark")

#: Juice Shop's own category labels, mapped to whether this engine dispatches a
#: class that could confirm that kind of flaw. Every category the target ships is
#: listed: an unlisted one would silently drop out of the denominator, and a
#: challenge nobody counted is a challenge nobody has to explain.
CATEGORY_ADDRESSABLE: dict[str, str] = {
    "Injection": "sql_injection / nosql_injection / command_injection / ssti",
    "XSS": "xss_reflected / xss_stored / xss_dom",
    "Broken Access Control": "idor",
    "Broken Authentication": "brute_force / jwt / weak_session",
    "Sensitive Data Exposure": "secrets_exposure / lfi / idor",
    "Improper Input Validation": "input_validation / constraint_violation / mass_assignment",
    "Cryptographic Issues": "weak_cryptography",
    "Security Misconfiguration": "security_headers / secrets_exposure",
    "Unvalidated Redirects": "open_redirect",
    "XXE": "xxe",
}

#: Categories with no dispatching class, and the reason. Held OUT of the
#: denominator, and named in the output so the exclusion is visible.
CATEGORY_NOT_ADDRESSABLE: dict[str, str] = {
    "Vulnerable Components": (
        "a published CVE against a dependency is a LEAD in this engine, never a "
        "finding — it must reduce to one of our own oracles on the live target"
    ),
    "Miscellaneous": "no vulnerability class; mostly UI scavenger hunts",
    "Observability Failures": "logging and monitoring gaps; no dispatched class",
    "Broken Anti Automation": "captcha / anti-automation; insecure_captcha is unimplemented",
    "Security through Obscurity": "no dispatched class",
    "Insecure Deserialization": "no dispatched class",
}

#: Above this, Juice Shop challenges stop being reachable vulnerabilities and
#: become multi-step puzzles gated on domain knowledge or out-of-band facts.
MAX_ADDRESSABLE_DIFFICULTY = 3

_TIMEOUT = 30


def fetch_challenges(base: str = BASE) -> list[dict[str, Any]]:
    """The target's own challenge list."""
    url = f"{base.rstrip('/')}/api/Challenges"
    with urllib.request.urlopen(url, timeout=_TIMEOUT) as response:  # noqa: S310 — local lab URL
        payload = json.loads(response.read().decode("utf-8", errors="replace"))
    data = payload.get("data") if isinstance(payload, dict) else payload
    if not isinstance(data, list):
        raise SystemExit(f"{url} did not return a challenge list")
    return [c for c in data if isinstance(c, dict)]


def recreate_and_verify_zero() -> list[dict[str, Any]]:
    """Recreate the container and REFUSE to continue unless the scoreboard is 0.

    A benchmark graded by a delta is only meaningful from a known start. A
    non-zero board means either a previous run's state survived or something else
    is touching the target, and in both cases the delta would attribute solves
    this engagement did not make.
    """
    print("recreating clinkz-juiceshop …", flush=True)
    subprocess.run(  # noqa: S603 — list-form, fixed argv
        [*COMPOSE, "up", "-d", "--force-recreate", "juiceshop"],
        capture_output=True,
        text=True,
        timeout=900,
        check=True,
    )
    for _ in range(90):
        try:
            challenges = fetch_challenges()
            break
        except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError):
            time.sleep(2)
    else:
        raise SystemExit("FATAL: Juice Shop did not come back up after the recreate")

    solved = [c for c in challenges if c.get("solved")]
    print(f"scoreboard: {len(solved)} solved of {len(challenges)}")
    if solved:
        raise SystemExit(
            f"FATAL: the scoreboard is not zero ({len(solved)} already solved: "
            f"{', '.join(c.get('key', '?') for c in solved[:8])}). A delta from a "
            f"dirty board attributes solves this engagement did not make. Stopping."
        )
    return challenges


def addressable(challenges: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """The derived addressable set, and any category the mapping does not know."""
    unknown = sorted(
        {
            str(c.get("category"))
            for c in challenges
            if c.get("category") not in CATEGORY_ADDRESSABLE
            and c.get("category") not in CATEGORY_NOT_ADDRESSABLE
        }
    )
    chosen = [
        c
        for c in challenges
        if c.get("category") in CATEGORY_ADDRESSABLE
        and int(c.get("difficulty") or 99) <= MAX_ADDRESSABLE_DIFFICULTY
    ]
    return sorted(chosen, key=lambda c: (c.get("category", ""), c.get("key", ""))), unknown


def run_engagement(
    authorization: Path, benchmark: Path, creds: Path
) -> tuple[str | None, int, float]:
    """Run the real pipeline against Juice Shop; return (engagement, rc, seconds)."""
    before = newest_engagement_dirs()
    started = time.time()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(  # noqa: S603 — list-form, operator-supplied paths
        [
            sys.executable,
            "-m",
            "clinkz",
            "scan",
            "--target",
            BASE,
            "--authorization",
            str(authorization),
            "--benchmark-profile",
            str(benchmark),
            "--creds",
            str(creds),
        ],
        capture_output=True,
        text=True,
        timeout=10800,
    )
    elapsed = time.time() - started
    # Captured stdout of a whole engagement, through the engine's redaction
    # chokepoint: whatever the run printed, this file keeps.
    write_redacted_text(
        RESULTS_DIR / "engagement_stdout.txt",
        proc.stdout + "\n=== STDERR ===\n" + proc.stderr,
    )
    new = newest_engagement_dirs() - before
    engagement = max(new, key=lambda n: (OUTPUTS / n).stat().st_mtime) if new else None
    return engagement, proc.returncode, elapsed


def _finding_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Every emitted finding, flattened to what a reconciliation needs."""
    rows = []
    for finding in report.get("findings", []):
        rows.append(
            {
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "target": finding.get("target"),
                "status": finding.get("status"),
                "description": (str(finding.get("description") or "").replace("\n", " "))[:400],
                "evidence_head": [
                    str(e).replace("\n", " ")[:220] for e in (finding.get("evidence") or [])[:3]
                ],
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authorization", required=True, type=Path)
    parser.add_argument("--benchmark-profile", required=True, type=Path, dest="benchmark")
    parser.add_argument("--creds", required=True, type=Path)
    parser.add_argument(
        "--skip-recreate",
        action="store_true",
        help="Reuse the running container (the zero check still runs and still refuses).",
    )
    args = parser.parse_args()
    for path in (args.authorization, args.benchmark, args.creds):
        if not path.is_file():
            raise SystemExit(f"FATAL: no such file: {path}")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # --- 1. known-zero start ------------------------------------------------
    if args.skip_recreate:
        challenges = fetch_challenges()
        solved_now = [c for c in challenges if c.get("solved")]
        print(f"scoreboard (no recreate): {len(solved_now)} solved of {len(challenges)}")
        if solved_now:
            raise SystemExit("FATAL: the scoreboard is not zero. Stopping.")
    else:
        challenges = recreate_and_verify_zero()

    target_set, unknown_categories = addressable(challenges)
    if unknown_categories:
        print(
            "WARNING: categories this mapping does not classify (excluded from BOTH "
            f"lists, so they are visible rather than silently dropped): {unknown_categories}"
        )
    print(
        f"addressable denominator: {len(target_set)} of {len(challenges)} "
        f"(category maps to a dispatched class AND difficulty <= "
        f"{MAX_ADDRESSABLE_DIFFICULTY})"
    )

    before_snapshot = {c.get("key") for c in challenges if c.get("solved")}
    write_redacted_json(
        RESULTS_DIR / "scoreboard_before.json",
        {
            "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "total_challenges": len(challenges),
            "solved_count": len(before_snapshot),
            "solved": sorted(before_snapshot),
            "addressable_count": len(target_set),
            "addressable": [
                {
                    "key": c.get("key"),
                    "name": c.get("name"),
                    "category": c.get("category"),
                    "difficulty": c.get("difficulty"),
                }
                for c in target_set
            ],
        },
    )

    # --- 2. the engagement --------------------------------------------------
    print("\nrunning the engagement (authenticated, benchmark profile ON) …", flush=True)
    engagement, rc, elapsed = run_engagement(args.authorization, args.benchmark, args.creds)
    print(f"engagement={engagement} rc={rc} {elapsed:.0f}s")
    if engagement is None:
        raise SystemExit("FATAL: no engagement directory was produced")

    # --- 3. after snapshot + delta -----------------------------------------
    after_challenges = fetch_challenges()
    after_by_key = {c.get("key"): c for c in after_challenges if c.get("solved")}
    newly = sorted(set(after_by_key) - before_snapshot)
    write_redacted_json(
        RESULTS_DIR / "scoreboard_after.json",
        {
            "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "engagement": engagement,
            "total_challenges": len(after_challenges),
            "solved_count": len(after_by_key),
            "solved": sorted(after_by_key),
            "newly_solved": [
                {
                    "key": k,
                    "name": after_by_key[k].get("name"),
                    "category": after_by_key[k].get("category"),
                    "difficulty": after_by_key[k].get("difficulty"),
                }
                for k in newly
            ],
        },
    )

    report = read_report(engagement)
    findings = _finding_rows(report)
    disclosure = read_artifact_scan(engagement)
    ledger = report.get("component_ledger") or {}

    addressable_keys = {c.get("key") for c in target_set}
    solved_addressable = [k for k in newly if k in addressable_keys]
    solved_outside = [k for k in newly if k not in addressable_keys]
    missed_addressable = [c for c in target_set if c.get("key") not in after_by_key]

    # --- 4. the reconciliation ---------------------------------------------
    print("\n" + "=" * 96)
    print("TWO INDEPENDENT NUMBERS")
    print("=" * 96)
    print(f"  challenges solved (target-confirmed) : {len(newly)}")
    print(f"    of which inside the addressable set: {len(solved_addressable)}/{len(target_set)}")
    print(f"    of which outside it                : {len(solved_outside)}")
    print(f"  findings emitted (engagement-reported): {len(findings)}")
    print(f"  unproven leads                        : {len(report.get('unproven_leads') or [])}")
    print(f"  research leads                        : {len(report.get('research_leads') or [])}")
    print(f"  confirmed chains                      : {len(report.get('confirmed_chains') or [])}")

    print("\nNEWLY SOLVED (the target's own verdict)")
    for key in newly:
        c = after_by_key[key]
        marker = "in-set " if key in addressable_keys else "OUT-SET"
        print(f"  + [{marker}] {key:44s} d{c.get('difficulty')} {c.get('category')}")
    if not newly:
        print("  (none)")

    print("\nFINDINGS EMITTED (to be reconciled against the above, one by one)")
    for row in findings:
        print(f"  - [{row['severity']}] {row['title']}")
        print(f"      target: {row['target']}")
        for line in row["evidence_head"][:1]:
            print(f"      proof : {line}")
    if not findings:
        print("  (none)")

    print(f"\nADDRESSABLE BUT NOT SOLVED ({len(missed_addressable)}) — each needs a stated cause")
    for c in missed_addressable:
        print(
            f"  ? {c.get('key'):44s} d{c.get('difficulty')} {c.get('category'):28s} "
            f"{str(c.get('name'))[:40]}"
        )

    print("\nHONESTY CONTROLS")
    print(f"  artifact scan : {'CLEAN' if disclosure.get('clean') else disclosure}")
    alarms = ledger.get("alarms") or []
    print(f"  ledger alarms : {len(alarms)}")
    for alarm in alarms:
        print(
            f"    ! {alarm.get('component')} [{alarm.get('kind')}]: "
            f"{','.join(alarm.get('alarms') or [])} "
            f"(invocations={alarm.get('invocations')}, "
            f"contributed={alarm.get('items_contributed')})"
        )

    out = RESULTS_DIR / "reconciliation.json"
    write_redacted_json(
        out,
        {
            "engagement": engagement,
            "returncode": rc,
            "seconds": round(elapsed, 1),
            "total_challenges": len(after_challenges),
            "addressable_count": len(target_set),
            "addressable_rule": (
                "category maps to a dispatched vulnerability class AND difficulty <= "
                f"{MAX_ADDRESSABLE_DIFFICULTY}"
            ),
            "solved_total": len(newly),
            "solved_keys": newly,
            "solved_in_addressable": solved_addressable,
            "solved_outside_addressable": solved_outside,
            "missed_addressable": [
                {
                    "key": c.get("key"),
                    "name": c.get("name"),
                    "category": c.get("category"),
                    "difficulty": c.get("difficulty"),
                }
                for c in missed_addressable
            ],
            "findings_emitted": findings,
            "unproven_leads": report.get("unproven_leads") or [],
            "artifact_scan": disclosure,
            "ledger_alarms": alarms,
            "ledger_never_invoked": ledger.get("never_invoked") or [],
            "category_addressable": CATEGORY_ADDRESSABLE,
            "category_not_addressable": CATEGORY_NOT_ADDRESSABLE,
            "unknown_categories": unknown_categories,
        },
    )
    print(f"\nwritten: {out.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
