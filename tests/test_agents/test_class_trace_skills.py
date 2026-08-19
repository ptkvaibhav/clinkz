"""``_CLASS_TRACE_SKILL`` is verified against the source, never trusted.

The class-coverage account answers "did this class reach an endpoint at all"
from the run's own trace, and it can only do that if it knows which ``skill``
string each class's methodology phases are written under. A hand-written map is
exactly the kind of second copy this codebase keeps catching: guess
``_test_x -> "x"`` and you are right for 23 of the 24 and silently wrong for
``_test_javascript_attacks`` (``js_attacks``) — and a class whose skill name is
mis-declared reports zero coverage, which reads identically to a class that
genuinely never ran. That is the failure the account exists to detect, produced
by the account itself.

So the declaration is checked the way ``test_parser_input_assumptions.py``
checks a parser's claim about its own input: by walking the source. For each
``_test_*`` method the call graph is followed through ``self._…`` helpers,
every ``_trace_methodology_phase(skill=…)`` literal is collected, the
cross-cutting skills are subtracted, and what remains must be exactly the one
skill the map declares.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from clinkz.agents import exploit as exploit_module
from clinkz.agents.exploit import (
    _CLASS_TRACE_SKILL,
    _CROSS_CUTTING_TRACE_SKILLS,
    _DETERMINISTIC_CATEGORY_ORDER,
    ExploitAgent,
)

SOURCE = Path(inspect.getfile(exploit_module))


def _agent_methods() -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    cls = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == ExploitAgent.__name__
    )
    return {
        node.name: node
        for node in cls.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _skills_and_calls(
    methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Per method: the skill literals it traces, and the sibling methods it calls."""
    skills: dict[str, set[str]] = {}
    calls: dict[str, set[str]] = {}
    for name, node in methods.items():
        traced: set[str] = set()
        called: set[str] = set()
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            func = sub.func
            fname = getattr(func, "attr", None) or getattr(func, "id", None)
            if fname == "_trace_methodology_phase":
                for kw in sub.keywords:
                    if kw.arg == "skill" and isinstance(kw.value, ast.Constant):
                        traced.add(kw.value.value)
            elif (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "self"
                and fname in methods
            ):
                called.add(fname)
        skills[name] = traced
        calls[name] = called
    return skills, calls


def _reachable_skills(
    root: str, skills: dict[str, set[str]], calls: dict[str, set[str]]
) -> set[str]:
    seen: set[str] = set()
    stack = [root]
    found: set[str] = set()
    while stack:
        method = stack.pop()
        if method in seen:
            continue
        seen.add(method)
        found |= skills.get(method, set())
        stack.extend(calls.get(method, ()))
    return found


@pytest.fixture(scope="module")
def reachable() -> dict[str, set[str]]:
    methods = _agent_methods()
    skills, calls = _skills_and_calls(methods)
    return {
        klass: _reachable_skills(klass, skills, calls)
        for klass in _DETERMINISTIC_CATEGORY_ORDER
        if klass in methods
    }


def test_every_dispatchable_class_declares_a_trace_skill() -> None:
    """A class the engine can dispatch but the map has never heard of is a class
    the coverage account silently reports as never having run."""
    assert set(_CLASS_TRACE_SKILL) == set(_DETERMINISTIC_CATEGORY_ORDER), (
        "declared: "
        f"{sorted(set(_CLASS_TRACE_SKILL) - set(_DETERMINISTIC_CATEGORY_ORDER))} not dispatchable; "
        f"{sorted(set(_DETERMINISTIC_CATEGORY_ORDER) - set(_CLASS_TRACE_SKILL))} dispatchable "
        "but undeclared"
    )


def test_each_declared_skill_is_the_one_that_class_actually_traces(
    reachable: dict[str, set[str]],
) -> None:
    """Read off the call graph, not off the naming convention."""
    for klass, declared in sorted(_CLASS_TRACE_SKILL.items()):
        own = reachable[klass] - _CROSS_CUTTING_TRACE_SKILLS
        assert declared in own, (
            f"{klass} declares skill {declared!r}, but the skills reachable from its "
            f"own call graph are {sorted(own)}. A skill the class cannot emit is "
            "evidence the coverage account will never see."
        )


def test_no_class_claims_a_skill_another_class_also_emits(
    reachable: dict[str, set[str]],
) -> None:
    """A skill two classes both write is evidence about neither.

    ``form_safety`` and friends are subtracted by name; this asserts nothing
    ELSE has quietly become shared, which would make one class's dispatch look
    like proof of another's.
    """
    for klass, declared in sorted(_CLASS_TRACE_SKILL.items()):
        others = {
            sibling
            for sibling, skills in reachable.items()
            if sibling != klass and declared in (skills - _CROSS_CUTTING_TRACE_SKILLS)
        }
        assert not others, (
            f"{klass} declares {declared!r}, but {sorted(others)} also emit it — "
            "the coverage account would read one class's phases as another's"
        )


def test_the_cross_cutting_list_holds_only_genuinely_shared_skills(
    reachable: dict[str, set[str]],
) -> None:
    """The subtraction must not be hiding a class's own skill.

    If a name on the cross-cutting list is reachable from exactly one class, it
    is that class's own skill and excluding it costs real coverage evidence.
    """
    for skill in sorted(_CROSS_CUTTING_TRACE_SKILLS):
        emitters = sorted(k for k, skills in reachable.items() if skill in skills)
        assert len(emitters) > 1, (
            f"{skill!r} is on the cross-cutting list but only {emitters} emits it; "
            "it is that class's own skill, not a shared one"
        )
