"""The fallback chains have to actually fall back.

``TOOL_CHAINS`` declares a preference order per capability. Three things have to
be true for that declaration to mean anything, and none of them was:

1. **A tool named in a chain must DECLARE that chain's capability.** ``find_tool``
   resolves through the capability map, which is built from each wrapper's own
   ``capabilities`` list — not from the chain. ``TOOL_CHAINS`` named ``httpx`` as
   whatweb's fallback while ``HttpxTool`` declared ``technology_detection``;
   ``nikto`` as nuclei's while ``NiktoTool`` declared
   ``web_vulnerability_scanning``; and ``subdomain_discovery`` was declared by
   nothing at all, so ``find_tool("subdomain_discovery")`` returned ``None`` on
   every call this project has ever made.

2. **The resolver must READ the declared order.** ``_capability_map`` is built by
   walking ``ToolBase.__subclasses__()``, i.e. in module import order. That was
   invisible while every chained capability resolved to exactly one wrapper —
   with one candidate any order is correct — and became live the moment (1) was
   fixed, silently returning httpx ahead of the whatweb the chain prefers.

3. **A chain must be able to run DIFFERENT tools.** ``try_until_sufficient``
   walks tool NAMES and its callbacks must resolve BY NAME, or a chain of four
   crawlers runs the first crawler four times.

These are gates rather than fixes, because each one was introduced by a change
that looked locally correct.

**These gates index the SHIPPED wrappers themselves, not a live resolver.**
``ToolResolver._discover`` walks ``ToolBase.__subclasses__()``, which is a
process-global registry, so every test module that defines a mock tool is
registered into every ``ToolResolver`` constructed afterwards — and
``_name_map[name] = cls`` is last-writer-wins, so a test double calling itself
``whatweb`` displaces the real ``WhatWebTool``. Harmless in production (nothing
imports ``tests``) but fatal to a gate: asserting over a live resolver makes the
result depend on which test modules pytest happened to import first, which is the
same host-dependence that makes a green suite meaningless. The question these
gates ask is about the codebase, so they read the codebase.
"""

from __future__ import annotations

import importlib
import inspect
from typing import Any

import pytest

from clinkz.tools.base import ToolBase
from clinkz.tools.resolver import _TOOL_MODULES, TOOL_CHAINS, ToolResolver


def _shipped_wrappers() -> dict[str, type[ToolBase]]:
    """``binary name → wrapper class`` for every wrapper the resolver ships.

    Indexed from ``_TOOL_MODULES`` — the resolver's OWN declaration of where
    wrappers live — rather than by scanning a package, so a wrapper outside
    ``clinkz.tools`` (the P7 browser oracle lives in ``clinkz.browser``) is not
    invisible to the gate, and a module dropped from that list fails here.
    """
    from clinkz.models.scope import EngagementScope

    scope = EngagementScope(name="_gate", targets=[])
    wrappers: dict[str, type[ToolBase]] = {}
    for module_path in _TOOL_MODULES:
        module = importlib.import_module(module_path)
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if not issubclass(obj, ToolBase) or obj is ToolBase:
                continue
            if obj.__module__ != module_path or inspect.isabstract(obj):
                continue
            try:
                wrappers[obj(scope=scope).name] = obj
            except Exception:  # noqa: BLE001 — a wrapper that cannot instantiate fails elsewhere
                continue
    return wrappers


SHIPPED: dict[str, type[ToolBase]] = _shipped_wrappers()


def _shipped_for_capability(capability: str) -> list[str]:
    """Shipped tool names declaring *capability*, in declared chain order."""
    chain = TOOL_CHAINS.get(capability, [])
    declaring = [name for name, cls in SHIPPED.items() if capability in cls.capabilities]
    return sorted(declaring, key=lambda n: (chain.index(n) if n in chain else len(chain), n))


@pytest.fixture(scope="module")
def resolver() -> ToolResolver:
    return ToolResolver()


@pytest.mark.parametrize("capability", sorted(TOOL_CHAINS))
def test_every_shipped_chain_member_declares_the_chain_capability(capability: str) -> None:
    """A chain entry the wrapper does not declare is a fallback that cannot fire.

    Only checked for chain entries we actually ship a wrapper for: a chain names
    ``gospider``/``feroxbuster``/``amass`` as declared preference order, not as a
    claim that they exist here.
    """
    for name in TOOL_CHAINS[capability]:
        cls = SHIPPED.get(name)
        if cls is None:
            continue
        assert capability in cls.capabilities, (
            f"TOOL_CHAINS['{capability}'] names '{name}', but {cls.__name__} declares "
            f"{cls.capabilities!r}. find_tool() resolves through the capability map, so "
            f"this entry can never be reached — the chain lists a fallback that cannot fire."
        )


@pytest.mark.parametrize("capability", sorted(TOOL_CHAINS))
def test_every_chained_capability_resolves_to_something(capability: str) -> None:
    """A declared capability nothing implements is a dead lookup, not a fallback.

    ``subdomain_discovery`` was exactly this: a three-entry chain that resolved
    to ``None`` because the one wrapper it ships declared a different name.
    """
    assert _shipped_for_capability(capability), (
        f"TOOL_CHAINS declares '{capability}' with chain {TOOL_CHAINS[capability]}, but no "
        f"shipped wrapper declares that capability — find_tool('{capability}') returns None."
    )


def test_resolution_order_follows_the_declared_chain(resolver: ToolResolver) -> None:
    """The order the resolver returns is the order the chain declares.

    Read off a live resolver deliberately — this is the one property that IS
    about ``_chain_ordered``'s behaviour rather than about the wrappers — but
    asserted as monotonicity over chain positions, which holds whatever extra
    test doubles the process has registered.
    """
    for capability, chain in TOOL_CHAINS.items():
        ordered = [resolver._class_to_name(c) for c in resolver._chain_ordered(capability)]
        positions = [chain.index(name) for name in ordered if name in chain]
        assert positions == sorted(positions), (
            f"'{capability}' resolves as {ordered}, which is not the declared preference "
            f"order {chain}. Import order is not a preference."
        )


def test_a_real_chain_falls_back_to_a_different_tool() -> None:
    """The end-to-end property: with the preferred tool gone, the next one runs.

    ``web_fingerprinting`` is the case that made this testable — it is the first
    capability in the project with two shipped implementations.
    """
    assert _shipped_for_capability("web_fingerprinting")[:2] == ["whatweb", "httpx"]

    class _WhatwebMissing(ToolResolver):
        """Only the two shipped fingerprinters exist, and whatweb is gone."""

        def __init__(self) -> None:
            super().__init__()
            self._capability_map["web_fingerprinting"] = [SHIPPED["whatweb"], SHIPPED["httpx"]]

        def is_available(self, tool_name: str) -> bool:
            return tool_name != "whatweb"

    fallback = _WhatwebMissing().find_tool("web_fingerprinting")
    assert fallback is not None
    assert fallback.name == "httpx", (
        "with whatweb unavailable the chain must reach its declared fallback, not "
        f"return an unavailable whatweb — got {fallback.name!r} available={fallback.available}"
    )
    assert fallback.available


@pytest.mark.asyncio
async def test_try_until_sufficient_runs_each_tool_in_the_chain_once() -> None:
    """A chain that runs its first tool N times is not a chain."""

    class _TwoToolResolver(ToolResolver):
        def is_available(self, tool_name: str) -> bool:
            return tool_name in ("katana", "gospider")

    ran: list[str] = []

    async def _run(tool_name: str, *args: Any) -> list[str]:
        ran.append(tool_name)
        return []  # never sufficient — force the whole chain to be walked

    resolver = _TwoToolResolver()
    await resolver.try_until_sufficient("web_crawling", 5, _run, "http://t/")
    assert ran == ["katana", "gospider"], (
        f"the chain ran {ran} — each declared, available tool must be tried once, in order"
    )


def test_a_capability_with_no_chain_is_left_alone(resolver: ToolResolver) -> None:
    """Chain ordering must not disturb capabilities that declare no chain."""
    assert "login" not in TOOL_CHAINS
    unchained = resolver._chain_ordered("login")
    assert [c.__name__ for c in unchained] == [
        c.__name__ for c in resolver._capability_map.get("login", [])
    ]


def test_every_shipped_wrapper_declares_at_least_one_capability() -> None:
    """A wrapper no capability reaches is code that can never run.

    Not the same question as the chain gates above: this catches a wrapper that
    ships and is nonetheless unreachable because nothing can ask for it.
    """
    silent = sorted(cls.__name__ for cls in SHIPPED.values() if not cls.capabilities)
    assert not silent, f"shipped wrappers declaring no capability at all: {silent}"
