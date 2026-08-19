"""A terminal account condition is discovered ONCE, not once per call.

Engagement ``f6a550a4`` made 79 Anthropic attempts and 76 of them came back
``400 invalid_request_error … Your credit balance is too low``. Each was a full
round-trip to re-learn a fact the first one had already established. The chain
behaved exactly as designed — an unexpected error is treated as retriable,
because finishing on a backup beats halting on a transient quirk — and that is
the right rule for a quirk and the wrong one for an account.

Two properties are pinned here, and the second matters as much as the first:
the condition stops the re-asking, and the *recognition* is narrow enough that
an ordinary bad request cannot cost the engagement its primary provider.
"""

from __future__ import annotations

from typing import Any

import pytest

from clinkz.llm.base import LLMClient, ProviderAccountError
from clinkz.llm.fallback import (
    ResilientLLMClient,
    reset_account_disabled_providers,
)


@pytest.fixture(autouse=True)
def _clean_breaker() -> Any:
    reset_account_disabled_providers()
    yield
    reset_account_disabled_providers()


# ---------------------------------------------------------------------------
# Recognition — narrow on purpose
# ---------------------------------------------------------------------------


class TestAccountErrorRecognition:
    @pytest.mark.parametrize(
        "message",
        [
            "Error code: 400 - {'type': 'error', 'error': {'type': 'invalid_request_error', "
            "'message': 'Your credit balance is too low to access the Anthropic API'}}",
            "authentication_error: invalid x-api-key",
            "permission_error: your account does not have access",
            "quota exceeded for your account",
        ],
    )
    def test_account_conditions_are_recognised(self, message: str) -> None:
        from clinkz.llm.anthropic_client import _is_account_error

        assert _is_account_error(Exception(message)) is True

    @pytest.mark.parametrize(
        "message",
        [
            "Error code: 400 - max_tokens: must be greater than 0",
            "Error code: 400 - messages.0.content: field required",
            "Error code: 429 - rate_limit_error",
            "Error code: 529 - overloaded_error",
            "Connection timeout",
        ],
    )
    def test_ordinary_faults_are_not_mistaken_for_account_conditions(self, message: str) -> None:
        """A false positive costs the run its primary provider. Stay narrow.

        A plain 400 is usually one malformed request, and the status code says
        nothing about the account — which is why the match is on the provider's
        own account language and never on the code.
        """
        from clinkz.llm.anthropic_client import _is_account_error

        assert _is_account_error(Exception(message)) is False


# ---------------------------------------------------------------------------
# The breaker
# ---------------------------------------------------------------------------


class _CountingClient(LLMClient):
    """A provider that always refuses with a given error, and counts attempts."""

    def __init__(self, error: Exception) -> None:
        self.error = error
        self.attempts = 0

    async def generate_text(self, prompt: Any, **_kw: object) -> str:
        self.attempts += 1
        raise self.error

    async def reason(self, messages: Any, tools: Any = None) -> Any:  # pragma: no cover
        raise self.error

    async def research(self, query: str) -> str:  # pragma: no cover
        raise self.error


class _WorkingClient(LLMClient):
    def __init__(self) -> None:
        self.attempts = 0

    async def generate_text(self, prompt: Any, **_kw: object) -> str:
        self.attempts += 1
        return "answer"

    async def reason(self, messages: Any, tools: Any = None) -> Any:  # pragma: no cover
        return None

    async def research(self, query: str) -> str:  # pragma: no cover
        return "x"


def _wire(monkeypatch: pytest.MonkeyPatch, clients: dict[str, LLMClient]) -> ResilientLLMClient:
    # "recon": the breaker's behaviour is role-independent, but "exploit" may no
    # longer rotate to a non-Claude provider at all, so a depletion test there
    # would be testing the policy refusal rather than the breaker.
    resilient = ResilientLLMClient("recon", override_chain=list(clients))
    monkeypatch.setattr(resilient, "_has_api_key", lambda provider: True)
    monkeypatch.setattr(resilient, "_get_or_create_client", lambda provider: clients[provider])
    resilient._clients = dict(clients)
    return resilient


@pytest.mark.asyncio
async def test_a_depleted_provider_is_asked_once_and_then_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    depleted = _CountingClient(ProviderAccountError("credit balance is too low"))
    backup = _WorkingClient()
    resilient = _wire(monkeypatch, {"anthropic": depleted, "gemini": backup})

    for _ in range(20):
        assert await resilient.generate_text("hello") == "answer"

    assert depleted.attempts == 1, "the account condition was re-discovered per call"
    assert backup.attempts == 20


@pytest.mark.asyncio
async def test_the_engagement_still_completes_on_the_backup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Terminal for the provider, never for the run."""
    depleted = _CountingClient(ProviderAccountError("credit balance is too low"))
    backup = _WorkingClient()
    resilient = _wire(monkeypatch, {"anthropic": depleted, "gemini": backup})
    assert await resilient.generate_text("hello") == "answer"


@pytest.mark.asyncio
async def test_the_breaker_is_shared_across_agents(monkeypatch: pytest.MonkeyPatch) -> None:
    """A depleted balance is a property of the KEY, not of one agent's client."""
    depleted = _CountingClient(ProviderAccountError("credit balance is too low"))
    backup = _WorkingClient()

    first = _wire(monkeypatch, {"anthropic": depleted, "gemini": backup})
    await first.generate_text("hello")
    assert depleted.attempts == 1

    second = _wire(monkeypatch, {"anthropic": depleted, "gemini": backup})
    await second.generate_text("hello")
    assert depleted.attempts == 1, "a second agent re-asked a provider already known depleted"


@pytest.mark.asyncio
async def test_a_transient_failure_does_not_disable_the_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: only an account condition takes a provider out of the chain."""
    from clinkz.llm.base import ServiceUnavailableError

    flaky = _CountingClient(ServiceUnavailableError("overloaded"))
    backup = _WorkingClient()
    resilient = _wire(monkeypatch, {"anthropic": flaky, "gemini": backup})

    for _ in range(5):
        await resilient.generate_text("hello")

    assert flaky.attempts == 5, "a transient provider was wrongly removed from the chain"


@pytest.mark.asyncio
async def test_the_disabling_is_recorded_on_the_ledger(monkeypatch: pytest.MonkeyPatch) -> None:
    from clinkz.observability import ledger as ledger_mod
    from clinkz.observability.ledger import ContributionLedger

    ledger = ContributionLedger("e")
    ledger_mod.set_active_ledger(ledger)
    try:
        depleted = _CountingClient(ProviderAccountError("credit balance is too low"))
        resilient = _wire(monkeypatch, {"anthropic": depleted, "gemini": _WorkingClient()})
        await resilient.generate_text("hello")
    finally:
        ledger_mod.set_active_ledger(None)

    record = next(r for r in ledger.records() if r.name == "llm:anthropic")
    assert record.failures == 1
    assert any("ProviderAccountError" in note for note in record.notes)
