#!/usr/bin/env python3
"""Guard: block credential shapes and ``.env`` files.

Scans every text blob for well-known credential shapes, and refuses any
``.env`` file (``.env.example``/``.sample``/``.template`` are allowed).

Two modes, matching ``outputs_guard.py``:

* **default — the staged index.** Invoked by the git pre-commit hook and the
  Claude Code PreToolUse hook. Both are local layers and both are skippable
  (per-clone ``core.hooksPath``; ``--no-verify``).
* ``--tree <rev>`` — **every path tracked at ``<rev>``.** Invoked by the
  ``leak-guard`` job in ``.github/workflows/ci.yml``: the fail-closed layer that
  no local config or flag can skip. Asserting on the resulting tree rather than
  on a diff means a rewritten base ref cannot hide an added blob.

The patterns are written so they do NOT match their own source text: the
character immediately after each fixed prefix in this file is ``[`` or ``*``,
which is outside the following character class, so this file passes its own
scan. Exit 0 = clean, exit 1 = a violation was found.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
]

# .env variants that are safe to track (documented templates, no real values).
_ENV_ALLOWED = {".env.example", ".env.sample", ".env.template"}

# Skip blobs larger than this (bytes) — pathological files, not credential stores.
_MAX_BLOB_BYTES = 5_000_000


def _staged_paths() -> list[str]:
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


def _blob(path: str, rev: str | None) -> str | None:
    """Content of ``path`` as text, or None if binary/oversize/missing.

    Reads the blob at ``rev`` in tree mode, and the staged blob otherwise.
    """
    spec = f"{rev}:{path}" if rev else f":{path}"
    proc = subprocess.run(["git", "show", spec], capture_output=True, check=False)
    if proc.returncode != 0 or len(proc.stdout) > _MAX_BLOB_BYTES:
        return None
    try:
        return proc.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _is_env_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    if name in _ENV_ALLOWED:
        return False
    return name == ".env" or name.startswith(".env.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refuse credential material and .env files.")
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

    violations: list[tuple[str, str]] = []
    for path in paths:
        if _is_env_file(path):
            violations.append((path, "environment file (.env)"))
            continue
        content = _blob(path, args.tree)
        if content is None:
            continue
        for label, pattern in _SECRET_PATTERNS:
            if pattern.search(content):
                violations.append((path, label))
                break
    if not violations:
        return 0
    sys.stderr.write("BLOCKED: credential material must never be committed.\n")
    for path, label in violations:
        sys.stderr.write(f"  - {path}: {label}\n")
    sys.stderr.write(
        "Move secrets to an untracked .env (gitignored) and read them via env vars.\n"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
