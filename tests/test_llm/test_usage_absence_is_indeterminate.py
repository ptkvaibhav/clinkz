"""Absence is not zero at the billing layer — over a COMPUTED domain.

The hole this closes
--------------------

``last_call_stats`` was assigned by exactly one client. ``AnthropicClient``
published it; ``GeminiClient._track_usage`` returned ``None`` after folding the
numbers into two private accumulators nobody reads, and ``OpenAIClient`` did the
same. ``ResilientLLMClient._collect_call_stats`` reads the field off whichever
client served the call and returns early when it is ``None``, so **a call served
by the fallback tail contributed zero** to the run totals, to the trace's token
field and to the engagement's spend ledger.

Zero in the cheap direction. Trace ``01b8e683`` holds a ``gemini-2.5-flash``
call written with ``"tokens": null``: the run that made it reported less spend
than it incurred, and a spend cap derived from those numbers fires late or never.

The second hole was one layer up and independent of the provider: stats were
collected in ``generate_text`` **alone**, so every ``reason`` and every
``research`` call contributed zero no matter who served it.

The third is the one the Anthropic client had registered against itself in a
docstring and deferred: an absent ``usage`` object leaves every counter at its
constructed ``0``, which is byte-identical to a call that consumed nothing.
That is invariant 80's fourth state — NOT DETERMINED — and a counter left at its
default cannot be told from one a producer set to zero.

Why the domain is computed
--------------------------

The guard-domain law (``.claude/skills/clinkz-dev/SKILL.md`` §4). A test naming
``gemini`` and ``openai`` would be a test written against the two clients
somebody remembered, and the failure is precisely that a client was forgotten.
So the domain is :data:`~clinkz.config.LLMProvider` — the engine's own declared
provider vocabulary — resolved to classes through the same
``_provider_client_class`` the runtime uses, and it is held in both directions:
a new client that is not in the vocabulary is also a red build.
"""

from __future__ import annotations

import ast
import inspect
import typing
from pathlib import Path

import pytest

from clinkz.config import LLMProvider
from clinkz.llm.base import CallStats, LLMClient, LLMUsageTotals
from clinkz.llm.fallback import ResilientLLMClient, _provider_client_class
from clinkz.llm.spend import SpendLedger

LLM_SRC = Path(inspect.getfile(LLMClient)).parent

#: Providers whose client cannot serve a call, and so cannot publish stats.
#: An allow-list entry with a substantive reason, never a silent skip.
CANNOT_SERVE: dict[str, str] = {
    "ollama": (
        "A stub whose __init__ raises NotImplementedError, so no instance can exist "
        "and no call can be served. It is in no fallback chain. The moment it gains "
        "a body it must publish last_call_stats like every sibling, and this entry "
        "is what has to be deleted for that to be true."
    ),
}


# ---------------------------------------------------------------------------
# The domain
# ---------------------------------------------------------------------------


def _declared_providers() -> set[str]:
    return set(typing.get_args(LLMProvider))


def _serving_clients() -> dict[str, type[LLMClient]]:
    """Every declared provider that can actually serve a call, as its class."""
    out: dict[str, type[LLMClient]] = {}
    for provider in sorted(_declared_providers()):
        if provider in CANNOT_SERVE:
            continue
        klass = _provider_client_class(provider)
        assert klass is not None, (
            f"provider {provider!r} is declared in LLMProvider but "
            "_provider_client_class returns no class for it"
        )
        out[provider] = klass
    return out


def _assigns_last_call_stats(klass: type[LLMClient]) -> bool:
    """Whether *klass*'s own source assigns ``self.last_call_stats``."""
    tree = ast.parse(Path(inspect.getfile(klass)).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Attribute)
                and target.attr == "last_call_stats"
                and isinstance(target.value, ast.Name)
                and target.value.id == "self"
            ):
                return True
    return False


# ---------------------------------------------------------------------------
# Direction 1 — every serving client publishes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", sorted(_serving_clients()))
def test_every_serving_client_publishes_last_call_stats(provider: str) -> None:
    klass = _serving_clients()[provider]
    assert _assigns_last_call_stats(klass), (
        f"{klass.__name__} never assigns self.last_call_stats, so every call it serves "
        "is invisible to _collect_call_stats: zero tokens in the run totals, zero in the "
        "trace, zero against the spend cap. That is what trace 01b8e683 recorded."
    )


def test_every_client_class_is_a_declared_provider() -> None:
    """The other direction: a new client cannot appear outside the vocabulary."""
    defined: set[str] = set()
    for path in sorted(LLM_SRC.glob("*_client.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and any(
                isinstance(b, ast.Name) and b.id == "LLMClient" for b in node.bases
            ):
                defined.add(node.name)
    reachable = {
        klass.__name__
        for provider in _declared_providers()
        if (klass := _provider_client_class(provider)) is not None
    }
    assert defined <= reachable, (
        f"client class(es) {sorted(defined - reachable)} are defined but reachable from no "
        "declared provider, so nothing above audits them"
    )


# ---------------------------------------------------------------------------
# Direction 2 — the seam collects on every interface method
# ---------------------------------------------------------------------------


def test_every_interface_method_collects_stats() -> None:
    """``reason``/``research``/``generate_text`` all fold their call in.

    The domain is the abstract methods of ``LLMClient``, so a fourth one added
    later is audited by the same assertion rather than quietly uninstrumented —
    which is how ``reason`` and ``research`` went un-metered.
    """
    interface = {
        name
        for name, value in vars(LLMClient).items()
        if getattr(value, "__isabstractmethod__", False)
    }
    assert interface, "LLMClient declares no abstract methods — the domain is empty"

    tree = ast.parse(Path(inspect.getfile(ResilientLLMClient)).read_text(encoding="utf-8"))
    resilient = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == "ResilientLLMClient"
    )
    missing = []
    for method in sorted(interface):
        impl = next(
            (
                n
                for n in resilient.body
                if isinstance(n, ast.AsyncFunctionDef | ast.FunctionDef) and n.name == method
            ),
            None,
        )
        assert impl is not None, f"ResilientLLMClient does not implement {method}"
        calls = {
            n.func.attr
            for n in ast.walk(impl)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        }
        if "_collect_call_stats" not in calls:
            missing.append(method)
    assert not missing, (
        f"ResilientLLMClient.{missing} dispatch through the chain without collecting call "
        "stats, so those calls contribute nothing to the run totals or the spend cap "
        "whoever serves them"
    )


# ---------------------------------------------------------------------------
# Direction 3 — absence is visible as absence, never summed as zero
# ---------------------------------------------------------------------------


def test_unreported_usage_is_not_a_measured_zero() -> None:
    blind = CallStats(provider="gemini", model="m")
    assert not blind.usage_reported
    measured = CallStats(provider="anthropic", model="m", usage_reported=True)
    assert measured.usage_reported

    totals = LLMUsageTotals()
    totals.add(blind)
    totals.add(measured)
    assert totals.calls == 2
    assert totals.calls_without_usage == 1
    assert not totals.usage_is_complete


def test_cache_hit_rate_is_none_when_nothing_reported() -> None:
    """A blind instrument and a perfect cache must not print the same number."""
    blind = LLMUsageTotals()
    blind.add(CallStats(provider="gemini", model="m"))
    assert blind.cache_hit_rate is None

    measured = LLMUsageTotals()
    measured.add(CallStats(provider="anthropic", model="m", usage_reported=True, input_tokens=100))
    assert measured.cache_hit_rate == 0.0


def test_spend_ledger_counts_what_it_could_not_measure() -> None:
    led = SpendLedger()
    led.record(model="m", input_tokens=100, output_tokens=10, usage_reported=True)
    led.record(model="m", input_tokens=0, output_tokens=0, usage_reported=False)

    assert led.total_tokens == 110
    assert led.indeterminate_calls == 1
    assert not led.tokens_are_complete
    assert not led.usd_is_complete, "an unmeasured call makes the USD figure a floor too"

    rendered = led.summary()
    assert rendered["calls"] == 2
    assert rendered["indeterminate_calls"] == 1
    assert rendered["tokens_are_complete"] is False
    assert rendered["by_model"]["m"]["calls_without_usage"] == 1
    assert "LOWER BOUND" in led.describe()


def test_spend_ledger_says_so_when_everything_was_measured() -> None:
    led = SpendLedger()
    led.record(model="m", input_tokens=100, output_tokens=10, usage_reported=True)
    rendered = led.summary()
    assert rendered["indeterminate_calls"] == 0
    assert rendered["tokens_are_complete"] is True
    assert "LOWER BOUND" not in led.describe()


def test_record_requires_the_declaration() -> None:
    """No default, because the permissive absence is the one that reads as free."""
    with pytest.raises(TypeError):
        SpendLedger().record(model="m", input_tokens=1, output_tokens=1)  # type: ignore[call-arg]
