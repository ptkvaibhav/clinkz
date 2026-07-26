#!/usr/bin/env python3
r"""Claude Code PreToolUse hook — leak-prevention backstop for agent commits.

The 44-artifact leak happened through the *agent* running ``git add -f
outputs/…`` then committing. This hook fires before any Bash command the agent
issues; when that command runs git's ``commit`` subcommand it runs
``outputs_guard`` and ``secret_guard`` against the targeted repo's staged index
and blocks (exit 2) on any violation. Every non-commit command returns 0
instantly. Wired in ``.claude/settings.json`` (PreToolUse / matcher "Bash");
reads the tool payload on stdin.

**Detection is deliberately fail-CLOSED.** A guard must prefer over-blocking to
under-blocking, so a shell segment is flagged when it invokes git *and* an exact
``commit`` token appears anywhere after it. No attempt is made to walk git's
global-option run: the previous pattern ``git\s+(?:-\S+\s+)*commit`` tried to
and under-blocked on every global option that takes a **separate** argument —
``git -C <path> commit`` and ``git -c k=v commit`` both returned exit 0, and
``git -C`` is a common agent idiom. Git's global options are an open set, so any
option-run pattern is one new option away from a bypass; matching the ``commit``
token cannot be interposed around. The cost is over-blocking oddities like
``git log --grep commit`` — the correct trade for a guard.

**Execution stays fail-OPEN**: any internal error returns 0, so a bug in this
hook can never brick a session's Bash. That makes this layer a convenience
backstop, not the hard gate. The two layers behind it:

* ``.githooks/pre-commit`` — per clone, once ``python scripts/bootstrap.py`` has
  set ``core.hooksPath``. Still skippable with ``--no-verify``.
* the ``leak-guard`` job in ``.github/workflows/ci.yml`` — **the fail-closed
  layer.** It runs server-side on every PR, so no local config, no
  ``--no-verify``, and no un-bootstrapped clone can skip it.

Index locality: the guards read the index of ``-C``'s target when the command
names one, and the session's own repo otherwise. A commit reached via
``cd <other-repo> && git commit`` is therefore *detected* but checked against
the session's index — CI is the layer that covers every other tree.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

# Shell operators that terminate one command and begin the next. Splitting on
# them keeps `git show HEAD && echo commit` out of the commit bucket.
_SEGMENT_SPLIT_RE = re.compile(r"[;\n|&()`]")

# A token that invokes git: bare `git`, or any path ending in git / git.exe.
_GIT_TOKEN_RE = re.compile(r"(?:^|[/\\])git(?:\.exe)?$", re.IGNORECASE)

# `-C <path>` relocates git's working directory, so it decides which index the
# guards must inspect.
_CHDIR_OPT = "-C"

# These relocate the repo too, but not in a way this hook can map to a directory
# the guards can read. Fail closed rather than check the wrong index.
_OPAQUE_REPO_OPTS = ("--git-dir", "--work-tree")

_GUARDS = ("outputs_guard.py", "secret_guard.py")


def _tokens(segment: str) -> list[str]:
    """Shell-split ``segment``, falling back to whitespace on unbalanced quotes."""
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def commit_tokens(command: str) -> list[str] | None:
    """Tokens of the first shell segment that runs git's ``commit`` subcommand.

    Returns None when no segment does. See the module docstring for why the
    match is on the ``commit`` token rather than on git's option grammar.
    """
    for segment in _SEGMENT_SPLIT_RE.split(command):
        tokens = _tokens(segment)
        git_at = next((i for i, tok in enumerate(tokens) if _GIT_TOKEN_RE.search(tok)), None)
        if git_at is not None and "commit" in tokens[git_at + 1 :]:
            return tokens
    return None


def _names_opaque_repo_opt(tokens: list[str]) -> bool:
    return any(
        tok == opt or tok.startswith(f"{opt}=") for tok in tokens for opt in _OPAQUE_REPO_OPTS
    )


def guard_cwd(tokens: list[str]) -> tuple[str | None, str | None]:
    """Resolve the directory to run the guards in.

    Returns ``(cwd, error)``. A ``cwd`` of None means the session's own repo. A
    non-None ``error`` means the targeted repo could not be resolved, so the
    commit must be blocked rather than cleared against the wrong index.
    """
    if _names_opaque_repo_opt(tokens):
        return None, "the command relocates the repo with --git-dir/--work-tree"
    chdirs = [
        tokens[i + 1] if i + 1 < len(tokens) else ""
        for i, tok in enumerate(tokens)
        if tok == _CHDIR_OPT
    ]
    if not chdirs:
        return None, None
    if len(chdirs) > 1:
        return None, f"multiple -C options ({', '.join(chdirs)})"
    target = chdirs[0]
    if not target or not Path(target).is_dir():
        return None, f"the -C target directory does not exist: {target!r}"
    return target, None


def _blocks(cwd: str | None) -> tuple[bool, str]:
    hooks_dir = Path(__file__).resolve().parent
    blocked = False
    messages: list[str] = []
    for guard in _GUARDS:
        proc = subprocess.run(
            [sys.executable, str(hooks_dir / guard)],
            capture_output=True,
            text=True,
            cwd=cwd,
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
    tokens = commit_tokens(command)
    if tokens is None:
        return 0
    try:
        cwd, error = guard_cwd(tokens)
        if error is None:
            blocked, message = _blocks(cwd)
        else:
            blocked, message = (
                True,
                f"BLOCKED: cannot inspect the repo this commit targets — {error}.\n"
                "Re-run from that directory with a literal path, so the guards read "
                "the index they are protecting.\n",
            )
    except Exception:  # noqa: BLE001 — fail open so a hook bug never blocks Bash
        return 0
    if blocked:
        sys.stderr.write(message)
        sys.stderr.write(
            "\nPreToolUse guard blocked this commit. Do NOT bypass with --no-verify: "
            "CI's leak-guard job fails the PR regardless.\n"
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
