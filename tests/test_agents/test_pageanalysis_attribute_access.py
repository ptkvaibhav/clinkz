"""No methodology reads an attribute ``PageAnalysis`` does not have.

Two of them did, and both killed a class outright while the suite stayed green:

* ``page.params`` (6 sites, 4 dispatchable classes) — the field is
  ``input_params``. ``_test_mass_assignment`` raised ``AttributeError`` on
  **5 of 5** dispatches in a live DVWA run and produced no finding, no lead and
  no phase event.
* ``page.headers`` (``_crypto_candidate_tokens``) — ``PageAnalysis`` never
  carried the response's headers at all, so ``_test_crypto``'s issued-token path
  could not run.

``__slots__`` makes the access raise rather than return ``None``, which should
have been loud. It was not, because the dispatcher wraps a task in a broad
handler that logs ``Task X on Y failed: ...`` at WARNING and moves on — so a
class that is 100% dead is indistinguishable, in the report, from a class that
correctly found nothing. Exactly the silent-degradation shape the contribution
ledger exists for, one level down.

A unit test per class cannot catch this: each one builds its own ``PageAnalysis``
and would have to guess the same wrong name to fail. So the check is structural
and reads the source — every attribute any method takes off a parameter
annotated ``PageAnalysis`` must be a slot, a method or a property of it.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from clinkz.agents import exploit as exploit_module

SOURCE = Path(inspect.getfile(exploit_module))


@pytest.fixture(scope="module")
def module_ast() -> ast.Module:
    return ast.parse(SOURCE.read_text(encoding="utf-8"))


def _class(tree: ast.Module, name: str) -> ast.ClassDef:
    return next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == name)


@pytest.fixture(scope="module")
def page_analysis_names(module_ast: ast.Module) -> set[str]:
    """Every name a ``PageAnalysis`` legitimately exposes."""
    node = _class(module_ast, "PageAnalysis")
    names: set[str] = set()
    for item in node.body:
        if isinstance(item, ast.Assign) and any(
            getattr(t, "id", "") == "__slots__" for t in item.targets
        ):
            names |= {e.value for e in item.value.elts}
        elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(item.name)
    return names


def test_the_slot_list_is_readable_and_non_trivial(page_analysis_names: set[str]) -> None:
    """A recogniser that matches nothing makes every other assertion vacuous."""
    assert len(page_analysis_names) > 10, (
        f"only parsed {sorted(page_analysis_names)} off PageAnalysis — the slot "
        "extraction is broken, and every check below would pass by accident"
    )
    assert {"url", "body", "status", "input_params"} <= page_analysis_names


def test_no_method_reads_an_attribute_pageanalysis_does_not_have(
    module_ast: ast.Module, page_analysis_names: set[str]
) -> None:
    """Read off the source, because the failure is per-dispatch and caught."""
    offenders: list[str] = []
    for cls_name in ("ExploitAgent",):
        cls = _class(module_ast, cls_name)
        for node in cls.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            page_args = {
                a.arg
                for a in [*node.args.args, *node.args.kwonlyargs]
                if a.annotation is not None and "PageAnalysis" in ast.unparse(a.annotation)
            }
            if not page_args:
                continue
            for sub in ast.walk(node):
                if (
                    isinstance(sub, ast.Attribute)
                    and isinstance(sub.value, ast.Name)
                    and sub.value.id in page_args
                    and not sub.attr.startswith("__")
                    and sub.attr not in page_analysis_names
                ):
                    offenders.append(
                        f"{cls_name}.{node.name} (line {sub.lineno}) reads "
                        f"{sub.value.id}.{sub.attr}"
                    )
    assert not offenders, (
        "these read an attribute PageAnalysis does not have. __slots__ makes each "
        "raise AttributeError at run time, and the dispatcher's broad handler turns "
        "that into a WARNING — so the class dies silently and its zero findings read "
        "as a clean target:\n  " + "\n  ".join(offenders)
    )


def test_the_check_would_actually_catch_the_bug_it_was_written_for(
    page_analysis_names: set[str],
) -> None:
    """The negative control: the two real names must not be in the legitimate set.

    Without this, a future edit that adds ``params`` as an alias would make the
    test above pass while the original defect (two spellings for one field, which
    is how the dead seam started) quietly returns.
    """
    assert "params" not in page_analysis_names, (
        "PageAnalysis grew a 'params' alias beside 'input_params'; two spellings "
        "for one field is what this test exists to prevent"
    )
    assert "headers" not in page_analysis_names, (
        "PageAnalysis grew a bare 'headers'; the response's headers are "
        "'response_headers' — a bare name does not say whose headers they are"
    )


def test_the_response_headers_slot_exists_and_is_lowercased() -> None:
    """``_crypto_candidate_tokens`` looks up ``set-cookie`` in lower case."""
    from clinkz.agents.exploit import PageAnalysis

    page = PageAnalysis(
        url="http://t/",
        body="",
        status=200,
        response_headers={"Set-Cookie": "sid=abcdefghijkl; Path=/", "Server": "x"},
    )
    assert page.response_headers["set-cookie"] == "sid=abcdefghijkl; Path=/"
    assert page.response_headers["server"] == "x"


def test_crypto_reads_a_token_out_of_the_response_it_was_given() -> None:
    """End to end over the seam that was dead: a Set-Cookie becomes a candidate."""
    from clinkz.agents.exploit import ExploitAgent, PageAnalysis

    page = PageAnalysis(
        url="http://t/",
        body="",
        status=200,
        response_headers={"Set-Cookie": "session=QUJDREVGR0hJSktM; Path=/; HttpOnly"},
    )
    tokens = ExploitAgent._crypto_candidate_tokens(page)
    assert ("session", "QUJDREVGR0hJSktM") in tokens


def test_a_page_with_no_response_headers_yields_no_tokens() -> None:
    """The default must be empty, not an exception — most pages set no cookie."""
    from clinkz.agents.exploit import ExploitAgent, PageAnalysis

    page = PageAnalysis(url="http://t/", body="", status=200)
    assert page.response_headers == {}
    assert ExploitAgent._crypto_candidate_tokens(page) == []
