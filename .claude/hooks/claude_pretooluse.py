#!/usr/bin/env python3
"""Claude Code PreToolUse hook — leak-prevention backstop for agent commits.

The 44-artifact leak happened through the *agent* running ``git add -f
outputs/…`` then committing. The git pre-commit hook catches that only when
``core.hooksPath`` is configured and ``--no-verify`` is not used. This hook
fires regardless of git config or ``--no-verify`` for any commit the agent
issues, so the outputs/secret guards cannot be silently skipped.

Wired in ``.claude/settings.json`` (PreToolUse / matcher "Bash"). Reads the tool
payload on stdin; if the command is a ``git commit``, runs ``outputs_guard`` and
``secret_guard`` against the staged index and blocks (exit 2) on any violation.
Every non-commit command returns 0 instantly. It fails OPEN on any internal
error (returns 0) so a hook bug can never brick the session's Bash — the git
pre-commit hook remains the fail-closed hard gate.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

# `git [global-opts] commit …` as a real subcommand (not `git show <commit>` etc.).
_COMMIT_RE = re.compile(r"(?:^|[\s;&|(])git\s+(?:-\S+\s+)*commit(?:\s|$)")

_GUARDS = ("outputs_guard.py", "secret_guard.py")


def _blocks() -> tuple[bool, str]:
    hooks_dir = Path(__file__).resolve().parent
    blocked = False
    messages: list[str] = []
    for guard in _GUARDS:
        proc = subprocess.run(
            [sys.executable, str(hooks_dir / guard)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            blocked = True
            messages.append(proc.stderr)
    return blocked, "".join(messages)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0
    if payload.get("tool_name") != "Bash":
        return 0
    command = (payload.get("tool_input") or {}).get("command", "")
    if not _COMMIT_RE.search(command):
        return 0
    try:
        blocked, message = _blocks()
    except Exception:  # noqa: BLE001 — fail open so a hook bug never blocks Bash
        return 0
    if blocked:
        sys.stderr.write(message)
        sys.stderr.write(
            "\nPreToolUse guard blocked this commit. Do NOT bypass with --no-verify.\n"
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
