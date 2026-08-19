"""A fallback is disqualifying, not invisible (Part B).

The failure this replaces: Gemini served 6 exploit plans and 6 false-positive
cross-checks across 9 engagements, and every one of those reports looked
exactly like a report it had not happened to. The fallback worked. That is what
made it invisible.
"""

from __future__ import annotations

from typing import Any

import pytest

from clinkz.config import Settings
from clinkz.llm import fallback as fallback_mod
from clinkz.llm.base import (
    AgentAction,
    LLMClient,
    LLMMessage,
    ProviderPolicyError,
    ServiceUnavailableError,
)
from clinkz.llm.degradation import (
    DegradationRegister,
    ProviderFallback,
    degradation_summary,
    set_active_degradation_register,
)
from clinkz.llm.fallback import CLAUDE_ONLY_ROLES, ResilientLLMClient
from clinkz.observability.ledger import ContributionLedger, LedgerAlarm, set_active_ledger


class _FakeLLM(LLMClient):
    """Returns each scripted item in turn; an exception item is raised."""

    def __init__(self, name: str, script: list[Any]) -> None:
        self.name = name
        self._script = list(script)
        self.calls = 0

    async def reason(self, messages: list[LLMMessage], tools: Any = None) -> AgentAction:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return await self.generate_text(query)

    async def generate_text(self, prompt: Any, **_kw: object) -> str:
        self.calls += 1
        item = self._script.pop(0) if self._script else "ok"
        if isinstance(item, Exception):
            raise item
        return str(item)


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch: pytest.MonkeyPatch):
    for var in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.setenv(var, "test-key")
    fallback_mod.reset_account_disabled_providers()
    register = DegradationRegister()
    set_active_degradation_register(register)
    ledger = ContributionLedger(engagement_id="t")
    set_active_ledger(ledger)
    yield register, ledger
    set_active_degradation_register(None)
    set_active_ledger(None)


def _register(monkeypatch: pytest.MonkeyPatch, clients: dict[str, LLMClient]) -> None:
    def factory(provider: str | None = None, **_kw: Any) -> LLMClient:
        return clients[str(provider)]

    monkeypatch.setattr(fallback_mod, "get_llm_client", factory)


# ---------------------------------------------------------------------------
# Baseline mode: a fallback is a hard failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["exploit", "research", "recon", "scan", "report"])
async def test_baseline_mode_hard_fails_on_any_fallback(
    role: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every role, not only the decision-bearing ones.

    Baseline mode exists for comparability, and comparability is broken by any
    stage: the 27%-vs-80% swing that motivated the model stamp was measured on
    security-header analysis, a scan/report-side call.
    """
    _register(
        monkeypatch,
        {
            "anthropic": _FakeLLM("anthropic", [ServiceUnavailableError("503")]),
            "gemini": _FakeLLM("gemini", ["should never be reached"]),
            "openai": _FakeLLM("openai", ["should never be reached"]),
        },
    )
    client = ResilientLLMClient(role, config=Settings(run_mode="baseline"))
    with pytest.raises(ProviderPolicyError, match="not a ladder"):
        await client.generate_text("hi")


@pytest.mark.asyncio
async def test_the_baseline_refusal_survives_a_broad_except_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The whole mechanism: every call site wraps LLM calls in except Exception.

    "Degrade gracefully" is correct for a provider quirk and is precisely how a
    run continues with the wrong model's answer in it, so the refusal is made
    structurally uncatchable the way KeyboardInterrupt is.
    """
    assert not issubclass(ProviderPolicyError, Exception)
    _register(
        monkeypatch,
        {
            "anthropic": _FakeLLM("anthropic", [ServiceUnavailableError("503")]),
            "gemini": _FakeLLM("gemini", ["cheap answer"]),
            "openai": _FakeLLM("openai", ["cheap answer"]),
        },
    )
    client = ResilientLLMClient("exploit", config=Settings(run_mode="baseline"))

    async def call_site_that_degrades_gracefully() -> str:
        try:
            return await client.generate_text("plan the exploits")
        except Exception:  # noqa: BLE001 — this is the shape being defeated
            return "deterministic fallback plan"

    with pytest.raises(ProviderPolicyError):
        await call_site_that_degrades_gracefully()


@pytest.mark.asyncio
async def test_baseline_mode_does_not_fire_when_the_primary_answers(
    monkeypatch: pytest.MonkeyPatch, _clean_state
) -> None:
    register, _ = _clean_state
    _register(
        monkeypatch,
        {
            "anthropic": _FakeLLM("anthropic", ["primary answer"]),
            "gemini": _FakeLLM("gemini", ["never"]),
            "openai": _FakeLLM("openai", ["never"]),
        },
    )
    client = ResilientLLMClient("exploit", config=Settings(run_mode="baseline"))
    assert await client.generate_text("hi") == "primary answer"
    assert register.baseline_eligible


@pytest.mark.asyncio
async def test_baseline_refuses_before_spending_the_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refused before the request leaves — not after buying an answer we discard."""
    gemini = _FakeLLM("gemini", ["cheap answer"])
    _register(
        monkeypatch,
        {
            "anthropic": _FakeLLM("anthropic", [ServiceUnavailableError("503")]),
            "gemini": gemini,
            "openai": _FakeLLM("openai", ["x"]),
        },
    )
    client = ResilientLLMClient("scan", config=Settings(run_mode="baseline"))
    with pytest.raises(ProviderPolicyError):
        await client.generate_text("hi")
    assert gemini.calls == 0


# ---------------------------------------------------------------------------
# Client mode: complete, stamp, disqualify
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_mode_completes_and_stamps(
    monkeypatch: pytest.MonkeyPatch, _clean_state
) -> None:
    register, _ = _clean_state
    _register(
        monkeypatch,
        {
            "anthropic": _FakeLLM("anthropic", [ServiceUnavailableError("503")]),
            "gemini": _FakeLLM("gemini", ["answer from the fallback"]),
            "openai": _FakeLLM("openai", ["x"]),
        },
    )
    client = ResilientLLMClient("exploit", config=Settings(run_mode="client"))
    assert await client.generate_text("plan") == "answer from the fallback"

    assert register.degraded
    assert not register.baseline_eligible
    event = register.events()[0]
    assert event.call_site == "exploit.generate_text"
    assert event.asked_provider == "anthropic"
    assert event.served_provider == "gemini"
    assert event.served_model == "gemini-3.7-flash"
    assert event.reason == "ServiceUnavailableError"
    assert event.decision_bearing is True


@pytest.mark.asyncio
async def test_a_non_decision_role_is_still_disqualifying_but_marked_apart(
    monkeypatch: pytest.MonkeyPatch, _clean_state
) -> None:
    register, _ = _clean_state
    _register(
        monkeypatch,
        {
            "anthropic": _FakeLLM("anthropic", [ServiceUnavailableError("503")]),
            "gemini": _FakeLLM("gemini", ["recon answer"]),
            "openai": _FakeLLM("openai", ["x"]),
        },
    )
    await ResilientLLMClient("recon", config=Settings(run_mode="client")).generate_text("hi")
    assert register.degraded
    assert register.events()[0].decision_bearing is False
    assert register.decision_bearing_events() == []


@pytest.mark.asyncio
async def test_eligibility_is_one_way(monkeypatch: pytest.MonkeyPatch, _clean_state) -> None:
    """A later clean call cannot un-shape an answer already in the findings."""
    register, _ = _clean_state
    _register(
        monkeypatch,
        {
            "anthropic": _FakeLLM("anthropic", [ServiceUnavailableError("503"), "clean"]),
            "gemini": _FakeLLM("gemini", ["degraded"]),
            "openai": _FakeLLM("openai", ["x"]),
        },
    )
    client = ResilientLLMClient("scan", config=Settings(run_mode="client"))
    await client.generate_text("first")
    await client.generate_text("second")
    assert not register.baseline_eligible


# ---------------------------------------------------------------------------
# The ledger alarms in EVERY mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["client", "baseline"])
async def test_the_ledger_alarms_on_fallback_regardless_of_mode(
    mode: str, monkeypatch: pytest.MonkeyPatch, _clean_state
) -> None:
    """Baseline raises, so its alarm is recorded by the attempt, not the success."""
    _, ledger = _clean_state
    _register(
        monkeypatch,
        {
            "anthropic": _FakeLLM("anthropic", [ServiceUnavailableError("503")]),
            "gemini": _FakeLLM("gemini", ["ok"]),
            "openai": _FakeLLM("openai", ["ok"]),
        },
    )
    client = ResilientLLMClient("scan", config=Settings(run_mode=mode))  # type: ignore[arg-type]
    try:
        await client.generate_text("hi")
    except ProviderPolicyError:
        pass

    anthropic_record = next(r for r in ledger.records() if r.name == "llm:anthropic")
    assert anthropic_record.failures >= 1, "the primary's failure is always recorded"
    if mode == "client":
        assert LedgerAlarm.FALLBACK_ACTIVATED in anthropic_record.alarms


# ---------------------------------------------------------------------------
# The summary shape
# ---------------------------------------------------------------------------


def test_a_clean_run_still_makes_the_claim() -> None:
    """A section that appears only on failure reads like a section nobody wrote."""
    set_active_degradation_register(DegradationRegister())
    try:
        summary = degradation_summary()
    finally:
        set_active_degradation_register(None)
    assert summary["provider_degraded"] is False
    assert summary["baseline_eligible"] is True
    assert summary["fallback_count"] == 0


def test_the_summary_shape_is_the_same_with_no_register_installed() -> None:
    """A directly invoked methodology has no run to disqualify."""
    set_active_degradation_register(None)
    assert degradation_summary()["baseline_eligible"] is True


def test_the_summary_names_call_sites_and_both_models() -> None:
    register = DegradationRegister()
    register.record(
        ProviderFallback(
            agent_role="exploit",
            method="generate_text",
            asked_provider="anthropic",
            asked_model="claude-sonnet-5",
            served_provider="gemini",
            served_model="gemini-3.7-flash",
            reason="RateLimitError",
            decision_bearing=True,
        )
    )
    summary = register.summary()
    assert summary["call_sites"] == ["exploit.generate_text"]
    assert summary["served_by"] == {"gemini/gemini-3.7-flash": 1}
    assert summary["decision_bearing_fallback_count"] == 1
    event = summary["events"][0]
    assert event["asked_model"] == "claude-sonnet-5"
    assert event["served_model"] == "gemini-3.7-flash"


def test_the_decision_bearing_roles_are_the_conclusion_producing_ones() -> None:
    assert CLAUDE_ONLY_ROLES == {"exploit", "research"}
