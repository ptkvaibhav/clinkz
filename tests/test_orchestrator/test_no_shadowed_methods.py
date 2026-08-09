"""A method defined twice in one class is silent, and it removed the first one.

``orchestrator.py`` carried two ``async def _verify_and_refresh_session`` — the
engagement-start one taking ``(login_url, sessions, valid_creds)``, and a later,
unrelated re-authentication body taking only ``self``. Python does not warn
about that; the second definition simply replaces the first. So every full
``clinkz scan`` died in ``_establish_authenticated_state`` with

    TypeError: _verify_and_refresh_session() takes 1 positional argument but 4 were given

and the unit suites never saw it, because they call the re-auth entry point
directly and never the establishment path.

Two guards, because they fail differently: a source-level scan catches any
future redefinition in these large modules, and a signature assertion pins the
specific call that broke.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from clinkz.orchestrator.orchestrator import OrchestratorAgent

#: The long-lived, heavily-edited modules where a duplicate is most likely and
#: least visible. Each is thousands of lines with many similarly-named helpers.
_GUARDED_MODULES = [
    "src/clinkz/orchestrator/orchestrator.py",
    "src/clinkz/agents/exploit.py",
    "src/clinkz/agents/scan.py",
    "src/clinkz/browser/oracle.py",
    "src/clinkz/tools/http_client.py",
    "src/clinkz/safety/governor.py",
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _duplicate_methods(path: Path) -> list[str]:
    """Return ``Class.method`` names defined more than once in one class body."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    duplicates: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        seen: set[str] = set()
        for item in node.body:
            if not isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            # A property/setter pair legitimately repeats the name.
            decorators = {
                d.attr if isinstance(d, ast.Attribute) else getattr(d, "id", "")
                for d in item.decorator_list
            }
            if decorators & {"setter", "deleter", "overload"}:
                continue
            if item.name in seen:
                duplicates.append(f"{node.name}.{item.name}")
            seen.add(item.name)
    return duplicates


@pytest.mark.parametrize("module", _GUARDED_MODULES)
def test_no_method_is_defined_twice_in_one_class(module: str) -> None:
    path = _repo_root() / module
    if not path.is_file():  # pragma: no cover - a rename should not fail the guard
        pytest.skip(f"{module} not present")
    duplicates = _duplicate_methods(path)
    assert duplicates == [], (
        f"{module} defines these methods twice in one class: {duplicates}. "
        "The later definition silently replaces the earlier one, which makes the "
        "first uncallable at runtime while every import still succeeds."
    )


def test_the_engagement_start_session_check_keeps_its_three_arguments() -> None:
    """The exact call that broke: ``_establish_authenticated_state`` passes three."""
    params = list(inspect.signature(OrchestratorAgent._verify_and_refresh_session).parameters)
    assert params == ["self", "login_url", "sessions", "valid_creds"]


def test_the_reauthentication_body_is_reachable_under_its_own_name() -> None:
    assert callable(OrchestratorAgent._reauthenticate_under_lock)
    params = list(inspect.signature(OrchestratorAgent._reauthenticate_under_lock).parameters)
    assert params == ["self"]
