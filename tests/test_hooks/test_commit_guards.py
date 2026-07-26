"""Regression tests for the commit-leak guards in ``.claude/hooks/``.

Three verified guard bypasses motivated these (LESSONS #34):

1. a fresh clone has no ``core.hooksPath`` and no ``.git/hooks/pre-commit``, so
   the git layer is inert and a plain ``git commit`` lands an ``outputs/`` leak
   in HEAD;
2. ``git commit --no-verify`` skips the git layer even when it *is* configured;
3. the PreToolUse hook's option-run regex missed ``git -C <path> commit`` and
   ``git -c k=v commit`` — both returned exit 0.

(1) and (2) are closed by the ``leak-guard`` CI job, which runs the guards
server-side in ``--tree`` mode — covered by the tree-mode tests below. (3) is
closed by fail-closed tokenized detection — covered by the detection matrix.

Note on the credential fixtures: every shape below is built by concatenation so
this file does not match ``secret_guard``'s own patterns. It is a tracked file
under ``tests/``, so CI scans it; a literal shape here would fail the repo's own
leak guard. Keep any new case split the same way.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

_HOOKS_DIR = Path(__file__).resolve().parents[2] / ".claude" / "hooks"

# Keep synthetic repos away from the developer's own hook config and signing.
_ISOLATE = ("-c", "core.hooksPath=.githooks-absent", "-c", "commit.gpgsign=false")
_IDENTITY = ("-c", "user.email=guard@test", "-c", "user.name=guard test")


def _load_hook():
    """Import ``claude_pretooluse.py`` by path — ``.claude/hooks`` is not a package."""
    path = _HOOKS_DIR / "claude_pretooluse.py"
    spec = importlib.util.spec_from_file_location("clinkz_pretooluse_hook", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_HOOK = _load_hook()


def _git_available() -> bool:
    try:
        proc = subprocess.run(["git", "--version"], capture_output=True, check=False)
    except (FileNotFoundError, OSError):
        return False
    return proc.returncode == 0


requires_git = pytest.mark.skipif(not _git_available(), reason="git is not installed")


def _commit(repo: Path, message: str) -> None:
    subprocess.run(
        ["git", *_IDENTITY, *_ISOLATE, "commit", "-q", "-m", message], cwd=repo, check=True
    )


def _make_repo(path: Path, *, staged_leak: bool = False) -> Path:
    """A one-commit git repo, optionally with ``outputs/leak.json`` staged."""
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    (path / "README.md").write_text("seed\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=path, check=True)
    _commit(path, "seed")
    if staged_leak:
        (path / "outputs").mkdir()
        (path / "outputs" / "leak.json").write_text('{"e":"leak"}\n', encoding="utf-8")
        subprocess.run(["git", "add", "-f", "outputs/leak.json"], cwd=path, check=True)
    return path


def _repo_with_committed_file(path: Path, filename: str, content: str) -> Path:
    repo = _make_repo(path)
    (repo / filename).write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "-f", filename], cwd=repo, check=True)
    _commit(repo, "add file")
    return repo


def _run_hook(command: str, cwd: Path) -> int:
    """Exit code of the PreToolUse hook for ``command`` — 2 = blocked, 0 = allowed."""
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    proc = subprocess.run(
        [sys.executable, str(_HOOKS_DIR / "claude_pretooluse.py")],
        input=payload,
        capture_output=True,
        text=True,
        cwd=cwd,
        check=False,
    )
    return proc.returncode


def _run_guard(guard: str, repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_HOOKS_DIR / guard), *args],
        capture_output=True,
        text=True,
        cwd=repo,
        check=False,
    )


# --------------------------------------------------------------------------- #
# Bypass 3 — detection must survive any interposed global option.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "command",
    [
        "git commit -m x",
        "git commit --no-verify -m x",
        "git -C /tmp/repo commit -m x",
        "git -c user.name=x commit -m x",
        "cd /tmp/repo && git commit -m x",
        "git -c a=b -C /tmp/repo commit --no-verify -m x",
        "git --git-dir=.git --work-tree=. commit -m x",
        "/usr/bin/git commit -m x",
        'git -C "/tmp/a dir" commit -m x',
        "echo hi; git commit -m x",
        "git commit",
    ],
)
def test_commit_is_detected(command: str) -> None:
    assert _HOOK.commit_tokens(command) is not None


@pytest.mark.parametrize(
    "command",
    [
        "git show HEAD",
        "git log --oneline",
        "git log --oneline -20",
        "git diff --cached --name-only",
        "git status --short",
        "git rev-parse HEAD^{commit}",
        "git log --grep=commit",
        "git commit-tree abc123",
        "git show HEAD && echo commit",
        "ruff check src/ tests/",
        "",
    ],
)
def test_non_commit_git_passes(command: str) -> None:
    assert _HOOK.commit_tokens(command) is None


def test_guard_cwd_defaults_to_the_session_repo() -> None:
    assert _HOOK.guard_cwd(["git", "commit", "-m", "x"]) == (None, None)


def test_guard_cwd_resolves_a_dash_c_target(tmp_path: Path) -> None:
    cwd, error = _HOOK.guard_cwd(["git", "-C", str(tmp_path), "commit"])
    assert error is None
    assert cwd == str(tmp_path)


def test_guard_cwd_blocks_a_missing_dash_c_target(tmp_path: Path) -> None:
    cwd, error = _HOOK.guard_cwd(["git", "-C", str(tmp_path / "nope"), "commit"])
    assert cwd is None
    assert error is not None


def test_guard_cwd_blocks_ambiguous_and_opaque_repo_options(tmp_path: Path) -> None:
    """Fail closed when the targeted index cannot be identified."""
    _, multi = _HOOK.guard_cwd(["git", "-C", str(tmp_path), "-C", str(tmp_path), "commit"])
    _, opaque = _HOOK.guard_cwd(["git", "--git-dir=.git", "commit"])
    assert multi is not None
    assert opaque is not None


# --------------------------------------------------------------------------- #
# PreToolUse hook, end to end against a real index.
# --------------------------------------------------------------------------- #


@requires_git
@pytest.mark.parametrize(
    "command",
    ["git commit -m x", "git commit --no-verify -m x", "cd . && git commit -m x"],
)
def test_hook_blocks_a_staged_outputs_leak(command: str, tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "dirty", staged_leak=True)
    assert _run_hook(command, cwd=repo) == 2


@requires_git
def test_hook_blocks_dash_c_commit_using_the_target_index(tmp_path: Path) -> None:
    """Bypass 3's actual payload: `git -C <dirty> commit` issued from a clean cwd.

    Detection alone is not enough — the guards must read the index of the repo
    ``-C`` names, not the session's, or a clean session index clears the commit.
    """
    dirty = _make_repo(tmp_path / "dirty", staged_leak=True)
    here = _make_repo(tmp_path / "here")
    assert _run_hook(f"git -C {dirty.as_posix()} commit -m x", cwd=here) == 2


@requires_git
def test_hook_allows_dash_c_commit_against_a_clean_target_index(tmp_path: Path) -> None:
    """Negative control: the block above must come from the leak, not from `-C` itself."""
    target = _make_repo(tmp_path / "target")
    here = _make_repo(tmp_path / "here")
    assert _run_hook(f"git -C {target.as_posix()} commit -m x", cwd=here) == 0


@requires_git
def test_hook_allows_a_clean_commit(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "clean")
    assert _run_hook("git commit -m x", cwd=repo) == 0


# --------------------------------------------------------------------------- #
# Bypasses 1 + 2 — the CI layer asserts on the resulting tree, not the index.
# --------------------------------------------------------------------------- #


@requires_git
def test_tree_mode_refuses_committed_outputs(tmp_path: Path) -> None:
    """Exactly what a fresh clone or `--no-verify` produces: the leak already in HEAD."""
    repo = _make_repo(tmp_path / "leaky", staged_leak=True)
    _commit(repo, "land the leak")
    proc = _run_guard("outputs_guard.py", repo, "--tree", "HEAD")
    assert proc.returncode == 1
    assert "outputs/leak.json" in proc.stderr


@requires_git
def test_tree_mode_passes_a_clean_tree(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "clean")
    assert _run_guard("outputs_guard.py", repo, "--tree", "HEAD").returncode == 0
    assert _run_guard("secret_guard.py", repo, "--tree", "HEAD").returncode == 0


@requires_git
@pytest.mark.parametrize(
    ("filename", "content"),
    [
        (".env", "ANTHROPIC_API_KEY=whatever\n"),
        ("anthropic.txt", "key = " + "sk-ant-" + "A" * 32 + "\n"),
        ("aws.txt", "id = " + "AKIA" + "B" * 16 + "\n"),
        ("github.txt", "token = " + "ghp_" + "c" * 36 + "\n"),
        ("key.pem", "-----BEGIN RSA " + "PRIVATE KEY-----\nx\n"),
    ],
)
def test_tree_mode_refuses_credential_material(tmp_path: Path, filename: str, content: str) -> None:
    repo = _repo_with_committed_file(tmp_path / "leaky", filename, content)
    proc = _run_guard("secret_guard.py", repo, "--tree", "HEAD")
    assert proc.returncode == 1
    assert filename in proc.stderr


@requires_git
def test_tree_mode_allows_the_env_template(tmp_path: Path) -> None:
    repo = _repo_with_committed_file(tmp_path / "ok", ".env.example", "ANTHROPIC_API_KEY=\n")
    assert _run_guard("secret_guard.py", repo, "--tree", "HEAD").returncode == 0


@requires_git
@pytest.mark.parametrize("guard", ["outputs_guard.py", "secret_guard.py"])
def test_tree_mode_refuses_an_unlistable_rev(guard: str, tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "clean")
    assert _run_guard(guard, repo, "--tree", "no-such-rev").returncode == 1


@requires_git
@pytest.mark.parametrize("guard", ["outputs_guard.py", "secret_guard.py"])
def test_an_unrecognised_flag_is_a_hard_error(guard: str, tmp_path: Path) -> None:
    """A bad CI invocation must fail loudly, not silently scan an empty index."""
    repo = _make_repo(tmp_path / "clean")
    assert _run_guard(guard, repo, "--range", "main..HEAD").returncode != 0


@pytest.mark.parametrize("guard", ["outputs_guard.py", "secret_guard.py"])
def test_ci_invokes_the_guards_in_tree_mode(guard: str) -> None:
    """The load-bearing half of the CI job is the ``--tree`` flag.

    Without it the guards scan the staged index, which on a runner is always
    empty — the job would pass forever while checking nothing. Assert the
    workflow keeps the flag rather than trusting a green tick.
    """
    workflow = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
    assert f".claude/hooks/{guard} --tree HEAD" in workflow.read_text(encoding="utf-8")


@requires_git
def test_this_repo_passes_its_own_ci_leak_guard() -> None:
    """The leak-guard job's exact invocation, against this checkout."""
    repo = Path(__file__).resolve().parents[2]
    assert _run_guard("outputs_guard.py", repo, "--tree", "HEAD").returncode == 0
    assert _run_guard("secret_guard.py", repo, "--tree", "HEAD").returncode == 0
