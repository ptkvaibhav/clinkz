#!/usr/bin/env python3
"""Guard: every always-loaded instruction file stays under its character budget.

WHY THIS EXISTS
---------------
``CLAUDE.md`` reached **152,205 characters against a ~150k load limit**. It grew
every week, and the bound it was approaching degrades by *truncating silently* —
so the first symptom would have been rules quietly not in effect, with nothing in
the transcript naming which ones. The highest-value content sat at the maximum-risk
position: ``## Pre-Push Verification`` and ``## Important Rules (NEVER)`` were the
LAST 3,120 characters of the file, so the first thing a cut would take is the gate
discipline and the hard NEVERs.

Same class as the guard-domain law: **a bound that degrades quietly is not a
bound.** This guard fails loudly at a budget far below the limit, so the file is
refused at commit time long before anything is cut.

THE UNIT
--------
Characters of decoded, newline-normalised text — the unit the context loader
counts. Deliberately NOT bytes: the file is dense with ``—`` and ``→`` (3 bytes
each) and uses CRLF on disk, so at the moment of the split ``wc -c`` said 155,526
where the loader saw 152,205 — a 2.2% gap, in the direction that flatters the
file. A guard that measures the wrong unit reports the wrong margin.

THE DOMAIN IS COMPUTED
----------------------
Per the guard-domain law (CLAUDE.md invariant 67): the domain is globbed from the
tree — every ``CLAUDE.md`` Claude Code can auto-load — so a new always-loaded file
cannot silently escape the budget. Only the CLASSIFICATION (which tier a file is
in) is hand-maintained, and a domain member with no tier **fails the guard**
rather than being skipped. A partition asserted over a domain that excludes its
unclassified members is a partition of whatever is left.

MODES
-----
``--staged``  measure the blobs in the git index (what the commit will contain).
              This is what the pre-commit hook runs: measuring the working tree
              there would let a staged-but-unsaved edit through.
default       measure the working tree (what CI and ``/gates`` run).

Exit 0 = every file within budget (warnings do not fail), exit 1 = over budget or
an unclassified domain member.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

# The real load limit this guard keeps the files away from. Not a threshold —
# it is the cliff, quoted so the printed margin means something.
LOAD_LIMIT = 150_000

# --- Tiers -------------------------------------------------------------------
# ALWAYS: read into every session, unconditionally. The budget is tight because
# every character is paid on every request of every task.
ALWAYS_BUDGET, ALWAYS_WARN = 60_000, 48_000
# ON_DEMAND: named by CLAUDE.md but read only when a task resembles a past
# failure. Looser, because it is not on the per-session bill — but still bounded,
# because it was split once already (PR #95) and has regrown since.
ON_DEMAND_BUDGET, ON_DEMAND_WARN = 50_000, 40_000

ALWAYS, ON_DEMAND = "always-loaded", "on-demand"

BUDGETS = {
    ALWAYS: (ALWAYS_BUDGET, ALWAYS_WARN),
    ON_DEMAND: (ON_DEMAND_BUDGET, ON_DEMAND_WARN),
}

# The hand-maintained half: which tier each instruction file is in, and why.
# An entry here that no longer exists in the tree is reported, not ignored.
TIERS = {
    "CLAUDE.md": (ALWAYS, "the lean operating core — loaded every session"),
    ".claude/LESSONS.md": (
        ON_DEMAND,
        "an index consulted only when a task resembles a past failure",
    ),
}

# Files that match the computed domain but are deliberately not instruction files
# for THIS project. Each needs a reason; an unreasoned skip is what this guard
# exists to refuse.
NOT_INSTRUCTIONS: dict[str, str] = {}


def _repo_root() -> str:
    return subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _tracked_files(root: str) -> list[str]:
    """Every tracked path, POSIX-separated and repo-relative."""
    proc = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=False, cwd=root
    )
    return [p.strip() for p in proc.stdout.splitlines() if p.strip()]


def computed_domain(root: str) -> set[str]:
    """Every instruction file the harness can auto-load, read off the tree.

    ``CLAUDE.md`` at any depth (Claude Code walks the directory chain), plus the
    files ``TIERS`` names explicitly — the latter so a declared entry that is
    deleted or renamed surfaces as a stale classification instead of vanishing.
    """
    found = {p for p in _tracked_files(root) if os.path.basename(p) == "CLAUDE.md"}
    return found | set(TIERS)


def measure(text: str) -> int:
    """Characters as the loader counts them: decoded, newlines normalised."""
    return len(text.replace("\r\n", "\n"))


def _read_worktree(root: str, rel: str) -> str | None:
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _read_staged(root: str, rel: str) -> str | None:
    proc = subprocess.run(
        ["git", "show", f":{rel}"],
        capture_output=True,
        check=False,
        cwd=root,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--staged",
        action="store_true",
        help="measure the git index rather than the working tree",
    )
    args = ap.parse_args()

    root = _repo_root()
    read = _read_staged if args.staged else _read_worktree
    where = "index" if args.staged else "working tree"

    domain = computed_domain(root)
    failed = False
    rows: list[tuple[str, str, int, int, int, str]] = []

    for rel in sorted(domain):
        if rel in NOT_INSTRUCTIONS:
            continue
        text = read(root, rel)
        if text is None:
            if rel in TIERS and not args.staged:
                # A declared file that is not in the tree: a stale classification.
                sys.stderr.write(
                    f"context-budget: BLOCKED — '{rel}' is classified in TIERS but "
                    f"is not present in the {where}. Remove the entry or restore "
                    f"the file; a classification that outlived what it described "
                    f"is how a guard's domain drifts.\n"
                )
                failed = True
            continue

        if rel not in TIERS:
            sys.stderr.write(
                f"context-budget: BLOCKED — '{rel}' is an always-loaded instruction "
                f"file with no tier in TIERS. Classify it (with the reason it is in "
                f"that tier); an unclassified domain member must never be skipped.\n"
            )
            failed = True
            continue

        tier, why = TIERS[rel]
        budget, warn = BUDGETS[tier]
        size = measure(text)

        if size > budget:
            state = "OVER"
            failed = True
        elif size > warn:
            state = "WARN"
        else:
            state = "ok"
        rows.append((rel, tier, size, budget, warn, state))

    width = max((len(r[0]) for r in rows), default=10)
    for rel, tier, size, budget, warn, state in rows:
        pct = 100.0 * size / budget
        line = (
            f"context-budget: {state:4} {rel:<{width}}  {size:>7,} / {budget:,} chars"
            f"  ({pct:.0f}% of budget, {100.0 * size / LOAD_LIMIT:.0f}% of the "
            f"{LOAD_LIMIT:,} load limit)  [{tier}]"
        )
        sys.stderr.write(line + "\n")
        if state == "OVER":
            sys.stderr.write(
                f"  BLOCKED: over budget by {size - budget:,} characters.\n"
                f"  {rel} is {why}. Move narrative into docs/ and leave the RULE "
                f"here — see CLAUDE.md 'Important Rules (NEVER)', last bullet.\n"
            )
        elif state == "WARN":
            sys.stderr.write(
                f"  WARNING: past {100.0 * warn / budget:.0f}% of budget "
                f"({warn:,} chars). Not blocking yet. Split before it is urgent — "
                f"the point of this guard is that the real limit gives no warning "
                f"at all.\n"
            )

    if failed:
        sys.stderr.write(
            "\ncontext-budget: FAILED. A bound that degrades quietly is not a "
            "bound — this one is loud on purpose.\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
