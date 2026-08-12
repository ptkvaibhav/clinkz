"""The mock audit, made mechanical.

Two seam defects shipped with the same shape and the same concealment: a
consumer read a field name the producer had never carried, the seam silently
returned nothing, and a test that had invented the same field name reported
success. ``FfufOutput`` has never had ``paths``/``directories``; ``SqlmapOutput``
has never had ``injectable``. In both cases a mock in this suite declared the
consumer's *assumption* rather than the producer's *contract*, so the suite
validated the consumer against a fiction — and a test that can only pass against
a fiction is worse than no test, because it is counted as coverage.

The audit that found those was manual. This makes it a gate:

  * **No test-local ``ToolOutput`` subclass may be returned by a mock tool** at a
    parser seam, except the handful that exist precisely to BE a broken producer
    (each named below with its reason). A mock returns the real model, so a field
    rename in a wrapper breaks these tests, which is the whole point of having
    them.
  * **Every discovery-capable wrapper declares its contract**, and every
    fingerprinting wrapper declares its own — checked over the real classes, so
    a new wrapper that forgets is caught here rather than by an engagement that
    quietly finds nothing.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from pathlib import Path

import pytest

import clinkz.tools
from clinkz.models.recon import DetectedComponent
from clinkz.tools.base import ToolOutput
from clinkz.tools.ffuf import FfufOutput
from clinkz.tools.httpx_tool import HttpxOutput
from clinkz.tools.katana import KatanaOutput
from clinkz.tools.nmap import NmapOutput
from clinkz.tools.whatweb import WhatWebOutput

_TESTS_ROOT = Path(__file__).resolve().parent.parent

# Test-local ToolOutput subclasses that are ALLOWED to be fictions, because the
# fiction is the subject under test rather than a stand-in for a real producer.
# Every entry needs a reason; an allowlist without reasons is how the original
# fictions would have been re-admitted.
_DELIBERATE_FICTIONS: dict[str, str] = {
    "_Undeclared": (
        "a producer that forgot to declare its contract — the negative control "
        "for the dead-seam alarm, which cannot be written with a real model "
        "because every real model declares correctly"
    ),
}


def _test_modules() -> list[str]:
    """Every test module, imported by path so class definitions are visible."""
    modules: list[str] = []
    for path in sorted(_TESTS_ROOT.rglob("test_*.py")):
        rel = path.relative_to(_TESTS_ROOT.parent)
        modules.append(".".join(rel.with_suffix("").parts))
    return modules


def _tool_output_subclasses_defined_in_tests() -> list[tuple[str, type[ToolOutput]]]:
    """``(module, class)`` for every ToolOutput subclass declared under tests/."""
    found: list[tuple[str, type[ToolOutput]]] = []
    for module_name in _test_modules():
        try:
            module = importlib.import_module(module_name)
        except Exception:  # noqa: BLE001 — a module that will not import fails elsewhere
            continue
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if not issubclass(obj, ToolOutput) or obj is ToolOutput:
                continue
            if not (obj.__module__ or "").startswith("tests."):
                continue  # a real model imported into the test — the good case
            if (module_name, obj) not in found:
                found.append((module_name, obj))
    return found


def test_no_test_local_tool_output_stands_in_for_a_real_producer() -> None:
    """A mock at a parser seam returns the REAL output model.

    The failure this prevents, verbatim: ``_MockFuzzOutput`` declared
    ``paths``/``directories``, names no real tool has ever carried, so the suite
    asserted a contract only the mock honoured while the production seam
    discarded 100% of ffuf's output.
    """
    offenders = [
        f"{module}.{cls.__name__}"
        for module, cls in _tool_output_subclasses_defined_in_tests()
        if cls.__name__ not in _DELIBERATE_FICTIONS
    ]
    assert not offenders, (
        "These ToolOutput subclasses are defined in tests/ rather than derived from a real "
        "tool wrapper. A mock whose shape does not come from the producer's declared "
        "interface tests the mock. Either return the real model, or — if the fiction IS the "
        "subject under test — add it to _DELIBERATE_FICTIONS with a reason: " + ", ".join(offenders)
    )


def test_every_deliberate_fiction_states_why_it_is_one() -> None:
    """An allowlist without reasons re-admits exactly what the audit removed."""
    for name, reason in _DELIBERATE_FICTIONS.items():
        assert reason.strip(), f"{name} is allow-listed with no reason"


# ---------------------------------------------------------------------------
# The producer side, over the REAL wrappers
# ---------------------------------------------------------------------------


def _real_output_models() -> list[type[ToolOutput]]:
    models: list[type[ToolOutput]] = []
    for info in pkgutil.iter_modules(clinkz.tools.__path__):
        module = importlib.import_module(f"clinkz.tools.{info.name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, ToolOutput) and obj is not ToolOutput and obj not in models:
                models.append(obj)
    return models


@pytest.mark.parametrize("model", [KatanaOutput, FfufOutput, HttpxOutput], ids=lambda m: m.__name__)
def test_surface_discovering_wrappers_declare_the_discovery_contract(
    model: type[ToolOutput],
) -> None:
    assert model.declares_discovery(), (
        f"{model.__name__} produces surface but declares no discovery contract — "
        "its consumer would read a seam that can never deliver"
    )


@pytest.mark.parametrize(
    "model", [WhatWebOutput, HttpxOutput, NmapOutput], ids=lambda m: m.__name__
)
def test_fingerprinting_wrappers_declare_the_component_contract(
    model: type[ToolOutput],
) -> None:
    assert model.declares_components(), (
        f"{model.__name__} fingerprints software but declares no component contract — "
        "the recon seam used to guess between `technologies` and `tech`, and a third "
        "spelling would have contributed nothing with nothing said about it"
    )


def test_a_non_fingerprinting_wrapper_is_honest_about_declaring_nothing() -> None:
    """The distinction that makes the dead-seam alarm possible at this seam too."""

    class Verdict(ToolOutput):
        detected: bool = False

    out = Verdict(tool_name="wafw00f", success=True)
    assert not type(out).declares_components()
    assert out.detected_components() == []


def test_every_real_output_model_returns_the_declared_types() -> None:
    """A declared contract that returns the wrong element type is still a fiction."""
    for model in _real_output_models():
        instance = model(tool_name="t", success=True)
        assert isinstance(instance.discovered_urls(), list)
        components = instance.detected_components()
        assert isinstance(components, list)
        assert all(isinstance(c, DetectedComponent) for c in components)
