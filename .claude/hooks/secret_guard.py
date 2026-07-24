#!/usr/bin/env python3
"""Pre-commit guard: block credential shapes and ``.env`` files from a commit.

Scans the staged content of every text blob for well-known credential shapes,
and refuses any staged ``.env`` file (``.env.example``/``.sample``/``.template``
are allowed). Invoked by the git pre-commit hook and the Claude Code PreToolUse
hook.

The patterns are written so they do NOT match their own source text: the
character immediately after each fixed prefix in this file is ``[`` or ``*``,
which is outside the following character class, so this file passes its own
scan. Exit 0 = clean, exit 1 = a violation was found (blocks the commit).
"""

from __future__ import annotations

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


def _staged_blob(path: str) -> str | None:
    """Staged content of ``path`` as text, or None if binary/oversize/missing."""
    proc = subprocess.run(
        ["git", "show", f":{path}"], capture_output=True, check=False
    )
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


def main() -> int:
    violations: list[tuple[str, str]] = []
    for path in _staged_paths():
        if _is_env_file(path):
            violations.append((path, "environment file (.env)"))
            continue
        content = _staged_blob(path)
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
