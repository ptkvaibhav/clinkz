#!/usr/bin/env python3
"""Pre-commit gate: ruff lint + format check, mirroring CI.

Runs only when a staged file lives under ``src/`` or ``tests/`` (a code change),
so doc/config commits are not taxed. Mirrors ``.github/workflows/ci.yml``:

    ruff check src/ tests/
    ruff format --check src/ tests/

Rationale: PR #84 went red in CI on a ``ruff format`` miss that a local
``ruff check`` alone did not catch — the format check is the load-bearing half.

Uses whatever ``ruff`` resolves on PATH. CI installs the pinned
``ruff==0.15.22`` via ``pip install -e '.[dev]'``; the resolved version is
printed so any local toolchain drift is visible. If ruff is not installed the
gate warns and passes (CI remains the hard backstop for lint).

Exit 0 = clean/skipped, exit 1 = lint or format check failed (blocks the commit).
"""

from __future__ import annotations

import subprocess
import sys


def _staged_paths() -> list[str]:
    proc = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True,
        text=True,
        check=False,
    )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _code_staged(paths: list[str]) -> bool:
    return any(
        p.endswith(".py") and (p.startswith("src/") or p.startswith("tests/"))
        for p in paths
    )


def _run_ruff(args: list[str]) -> int | None:
    """Run ruff; return its exit code, or None if ruff is not installed."""
    try:
        return subprocess.run(["ruff", *args], check=False).returncode
    except FileNotFoundError:
        return None


def main() -> int:
    if not _code_staged(_staged_paths()):
        return 0

    version = subprocess.run(
        ["ruff", "--version"], capture_output=True, text=True, check=False
    ).stdout.strip()
    if not version:
        sys.stderr.write("gates: ruff not found on PATH — skipping (CI enforces lint).\n")
        return 0
    sys.stderr.write(f"gates: {version} (CI pins ruff==0.15.22)\n")

    if _run_ruff(["check", "src/", "tests/"]) not in (0, None):
        sys.stderr.write("BLOCKED: ruff check failed. Fix the lint errors above.\n")
        return 1
    if _run_ruff(["format", "--check", "src/", "tests/"]) not in (0, None):
        sys.stderr.write("BLOCKED: ruff format --check failed. Run: ruff format src/ tests/\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
