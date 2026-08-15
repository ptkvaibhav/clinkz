"""Juice Shop scoreboard snapshots — external, unforgeable validation.

OWASP Juice Shop marks a challenge solved only when it is genuinely exploited,
and exposes that state at ``/api/Challenges``. That makes the target itself the
grader: snapshot before a run, snapshot after, and the delta is what Clinkz
actually solved — not what Clinkz says it solved.

The two numbers are independent and both are reported, because each mismatch
means something different and neither may be assumed away:

* **solved but not reported** — the engagement exercised a real vulnerability
  and emitted nothing. A reporting gap, and just as serious as the reverse.
* **reported but not solved** — either a genuine finding outside the challenge
  set (the challenge set is not a complete vulnerability inventory), or a
  phantom. Which one it is has to be reasoned from the finding's own evidence.

Usage::

    python scripts/juiceshop_scoreboard_delta.py snapshot before.json
    python scripts/juiceshop_scoreboard_delta.py delta before.json after.json

``--base`` overrides the target (default ``http://localhost:3000``).
This is a validation harness for one benchmark, not engine code: nothing in
``src/clinkz`` imports it, and no methodology knows this file exists.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _artifact_io import write_redacted_json  # noqa: E402

DEFAULT_BASE = "http://localhost:3000"
_TIMEOUT = 30


def fetch_challenges(base: str) -> list[dict[str, Any]]:
    """The target's own challenge list, or raise with a readable message."""
    url = f"{base.rstrip('/')}/api/Challenges"
    with urllib.request.urlopen(url, timeout=_TIMEOUT) as response:  # noqa: S310 — operator-supplied lab URL
        payload = json.loads(response.read().decode("utf-8", errors="replace"))
    data = payload.get("data") if isinstance(payload, dict) else payload
    if not isinstance(data, list):
        raise SystemExit(f"{url} did not return a challenge list")
    return [c for c in data if isinstance(c, dict)]


def snapshot(base: str, out_path: Path) -> dict[str, Any]:
    """Write a scoreboard snapshot and return it."""
    challenges = fetch_challenges(base)
    solved = sorted(
        (
            {
                "key": c.get("key", ""),
                "name": c.get("name", ""),
                "category": c.get("category", ""),
                "difficulty": c.get("difficulty", 0),
            }
            for c in challenges
            if c.get("solved")
        ),
        key=lambda c: c["key"],
    )
    document = {
        "target": base,
        "captured_at": datetime.now(UTC).isoformat(),
        "total_challenges": len(challenges),
        "solved_count": len(solved),
        "solved": solved,
    }
    write_redacted_json(out_path, document)
    return document


def delta(before_path: Path, after_path: Path) -> int:
    """Print the before/after delta. Returns the number newly solved."""
    before = json.loads(before_path.read_text(encoding="utf-8"))
    after = json.loads(after_path.read_text(encoding="utf-8"))

    before_keys = {c["key"] for c in before["solved"]}
    after_by_key = {c["key"]: c for c in after["solved"]}
    newly = [after_by_key[k] for k in sorted(set(after_by_key) - before_keys)]
    lost = sorted(before_keys - set(after_by_key))

    print(f"target             : {after.get('target')}")
    print(f"challenges shipped : {after.get('total_challenges')}")
    print(f"solved before      : {before['solved_count']}")
    print(f"solved after       : {after['solved_count']}")
    print(f"NEWLY SOLVED       : {len(newly)}")
    if lost:
        # Only possible if the instance was reset mid-run; say so rather than
        # reporting a negative delta as if it meant something.
        print(f"NO LONGER SOLVED   : {len(lost)} ({', '.join(lost)}) — was the target reset?")
    print()
    for challenge in newly:
        print(
            f"  + {challenge['key']:42s} {challenge['category']:26s} "
            f"d{challenge['difficulty']}  {challenge['name']}"
        )
    if not newly:
        print("  (none)")
    return len(newly)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--base", default=DEFAULT_BASE)
    sub = parser.add_subparsers(dest="command", required=True)

    snap = sub.add_parser("snapshot", help="write a scoreboard snapshot")
    snap.add_argument("out", type=Path)

    diff = sub.add_parser("delta", help="print the delta between two snapshots")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)

    args = parser.parse_args(argv)
    if args.command == "snapshot":
        document = snapshot(args.base, args.out)
        print(
            f"{args.out}: {document['solved_count']}/{document['total_challenges']} solved "
            f"at {document['captured_at']}"
        )
        return 0
    delta(args.before, args.after)
    return 0


if __name__ == "__main__":
    sys.exit(main())
