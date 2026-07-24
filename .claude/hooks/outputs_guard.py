#!/usr/bin/env python3
"""Pre-commit guard: hard-refuse any staged path under ``outputs/``.

Rationale: 44 engagement run artifacts once reached a PUBLIC repo under
``outputs/`` and required a full git-history rewrite to purge. ``outputs/`` is
gitignored, but ``git add -f`` bypasses ``.gitignore`` — this guard is the
backstop that fires *regardless* of ``-f``. Invoked by the git pre-commit hook
(``.githooks/pre-commit``) and the Claude Code PreToolUse hook so it cannot be
silently skipped.

Exit 0 = clean, exit 1 = a violation was found (blocks the commit).
"""

from __future__ import annotations

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


def main() -> int:
    offenders = [p for p in _staged_paths() if p == "outputs" or p.startswith("outputs/")]
    if not offenders:
        return 0
    sys.stderr.write(
        "BLOCKED: run artifacts under outputs/ must never be committed "
        "(gitignored + local-only by policy).\n"
    )
    for path in offenders:
        sys.stderr.write(f"  - {path}\n")
    sys.stderr.write(
        "outputs/ is retained by the operator, not the repo. Unstage with:\n"
        "  git restore --staged outputs/\n"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
