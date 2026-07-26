#!/usr/bin/env python3
"""Guard: hard-refuse any path under ``outputs/``.

Rationale: 44 engagement run artifacts once reached a PUBLIC repo under
``outputs/`` and required a full git-history rewrite to purge. ``outputs/`` is
gitignored, but ``git add -f`` bypasses ``.gitignore`` — this guard is the
backstop that fires *regardless* of ``-f``.

Two modes:

* **default — the staged index.** Invoked by the git pre-commit hook
  (``.githooks/pre-commit``) and the Claude Code PreToolUse hook
  (``claude_pretooluse.py``). Both are *local* layers, and both are skippable:
  ``core.hooksPath`` is per-clone config that no clone has until
  ``python scripts/bootstrap.py`` runs, and ``--no-verify`` skips the git hook
  outright.
* ``--tree <rev>`` — **every path tracked at ``<rev>``.** Invoked by the
  ``leak-guard`` job in ``.github/workflows/ci.yml``: the fail-closed layer, so
  no local config or flag can skip it. It asserts on the resulting *tree* rather
  than on a diff, so neither a rewritten base ref nor a squashed range can hide
  an added path.

Exit 0 = clean, exit 1 = a violation was found.
"""

from __future__ import annotations

import argparse
import subprocess
import sys


def _staged_paths() -> list[str]:
    """Return added/copied/modified/renamed paths in the staged index."""
    proc = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True,
        text=True,
        check=False,
    )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _tree_paths(rev: str) -> list[str] | None:
    """Every path tracked at ``rev``, or None if the tree cannot be listed."""
    proc = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", rev],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refuse any tracked path under outputs/.")
    parser.add_argument(
        "--tree",
        metavar="REV",
        help="scan every path tracked at REV instead of the staged index (CI mode)",
    )
    args = parser.parse_args(argv)

    if args.tree:
        paths = _tree_paths(args.tree)
        if paths is None:
            sys.stderr.write(
                f"BLOCKED: cannot list the tree at {args.tree!r} — "
                "refusing to pass an unverified revision.\n"
            )
            return 1
    else:
        paths = _staged_paths()

    offenders = [p for p in paths if p == "outputs" or p.startswith("outputs/")]
    if not offenders:
        return 0
    sys.stderr.write(
        "BLOCKED: run artifacts under outputs/ must never be committed "
        "(gitignored + local-only by policy).\n"
    )
    for path in offenders:
        sys.stderr.write(f"  - {path}\n")
    if args.tree:
        sys.stderr.write(
            "outputs/ is retained by the operator, not the repo. Drop it from the "
            "branch with:\n  git rm -r --cached outputs/\n"
        )
    else:
        sys.stderr.write(
            "outputs/ is retained by the operator, not the repo. Unstage with:\n"
            "  git restore --staged outputs/\n"
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
