"""The LLM spend cap — the engagement's third bound.

Tokens are measured and always enforceable. Dollars are derived from a rate
card only the operator has, so a USD cap without declared prices is refused at
startup rather than silently enforcing nothing.
"""

from __future__ import annotations

import pytest

from clinkz.llm.spend import (
    ModelPrice,
    SpendCapError,
    SpendLedger,
    load_price_table,
    record_spend,
    set_active_spend_ledger,
    spend_cap_exceeded,
    spend_summary,
)

PRICES = {"claude-sonnet-5": ModelPrice(3.0, 15.0)}


@pytest.fixture
def ledger():
    active = SpendLedger()
    set_active_spend_ledger(active)
    yield active
    set_active_spend_ledger(None)


# ---------------------------------------------------------------------------
# Tokens are measured
# ---------------------------------------------------------------------------


def test_a_token_cap_needs_no_rate_card() -> None:
    led = SpendLedger(token_cap=1000)
    assert led.exceeded() == ""
    led.record(model="anything", input_tokens=600, output_tokens=500)
    assert "token cap reached" in led.exceeded()


def test_the_cap_is_checked_before_a_call_not_after() -> None:
    """Stops AT the cap rather than one unbounded call past it."""
    led = SpendLedger(token_cap=100)
    led.record(model="m", input_tokens=100, output_tokens=0)
    assert led.exceeded(), "at the cap counts as reached"


def test_usage_is_tallied_per_model() -> None:
    led = SpendLedger(prices=PRICES)
    led.record(model="claude-sonnet-5", input_tokens=1000, output_tokens=200)
    led.record(model="gemini-3.7-flash", input_tokens=50, output_tokens=10)
    by_model = led.summary()["by_model"]
    assert by_model["claude-sonnet-5"]["calls"] == 1
    assert by_model["claude-sonnet-5"]["input_tokens"] == 1000
    assert by_model["gemini-3.7-flash"]["usd"] is None, "no rate declared"
    assert led.summary()["total_tokens"] == 1260


# ---------------------------------------------------------------------------
# Dollars are derived, and only where a rate was declared
# ---------------------------------------------------------------------------


def test_cost_is_computed_from_the_declared_rate() -> None:
    led = SpendLedger(prices=PRICES)
    led.record(model="claude-sonnet-5", input_tokens=1_000_000, output_tokens=1_000_000)
    assert led.usd_spent == pytest.approx(18.0)
    assert led.usd_is_complete


def test_an_unpriced_model_makes_the_total_a_lower_bound() -> None:
    """Recorded, never estimated — the report has to be able to say so."""
    led = SpendLedger(prices=PRICES)
    led.record(model="claude-sonnet-5", input_tokens=1_000_000, output_tokens=0)
    led.record(model="mystery-model", input_tokens=5_000_000, output_tokens=5_000_000)
    assert led.usd_spent == pytest.approx(3.0)
    assert not led.usd_is_complete
    assert led.summary()["unpriced_models"] == ["mystery-model"]
    assert "lower bound" in led.describe()


def test_a_usd_cap_without_a_rate_card_is_refused_at_startup() -> None:
    """A cap that silently stops enforcing is indistinguishable from no cap."""
    led = SpendLedger(usd_cap=5.0)
    with pytest.raises(SpendCapError) as excinfo:
        led.assert_enforceable(["claude-sonnet-5", "gemini-3.7-flash"])
    message = str(excinfo.value)
    assert "claude-sonnet-5" in message
    assert "gemini-3.7-flash" in message
    assert "CLINKZ_LLM_PRICES" in message
    assert "--token-cap" in message, "names the measured alternative"


def test_a_usd_cap_with_every_model_priced_is_accepted() -> None:
    led = SpendLedger(usd_cap=5.0, prices={"a": ModelPrice(1, 1), "b": ModelPrice(1, 1)})
    led.assert_enforceable(["a", "b"])


def test_no_usd_cap_means_no_rate_card_is_required() -> None:
    """Accounting still runs; only the CAP needs prices."""
    SpendLedger().assert_enforceable(["anything", "at", "all"])


def test_the_usd_cap_fires_on_the_declared_rate() -> None:
    led = SpendLedger(usd_cap=1.0, prices=PRICES)
    assert led.exceeded() == ""
    led.record(model="claude-sonnet-5", input_tokens=1_000_000, output_tokens=0)
    assert "spend cap reached" in led.exceeded()


# ---------------------------------------------------------------------------
# The rate card
# ---------------------------------------------------------------------------


def test_no_declared_prices_is_an_empty_table_not_a_default() -> None:
    """A built-in rate card would be right the day it was written."""
    assert load_price_table("") == {}
    assert load_price_table("   ") == {}


def test_a_declared_rate_card_parses() -> None:
    table = load_price_table('{"m": {"input": 3, "output": 15}}')
    assert table["m"].input_usd_per_mtok == 3.0
    assert table["m"].output_usd_per_mtok == 15.0


@pytest.mark.parametrize(
    "raw",
    ["not json", "[1,2]", '{"m": {"input": 3}}', '{"m": {"input": "x", "output": 1}}'],
)
def test_a_malformed_rate_card_is_refused_rather_than_half_read(raw: str) -> None:
    """A half-read table would under-count silently."""
    with pytest.raises(SpendCapError):
        load_price_table(raw)


# ---------------------------------------------------------------------------
# Absent by default
# ---------------------------------------------------------------------------


def test_no_ledger_installed_means_no_cap_and_no_accounting() -> None:
    set_active_spend_ledger(None)
    record_spend(model="m", input_tokens=10, output_tokens=10)
    assert spend_cap_exceeded() == ""
    assert spend_summary()["total_tokens"] == 0


def test_the_module_level_recorder_reaches_the_active_ledger(ledger) -> None:
    record_spend(model="m", input_tokens=10, output_tokens=5)
    assert ledger.total_tokens == 15
    assert spend_summary()["total_tokens"] == 15


def test_the_summary_states_the_caps_it_ran_under(ledger) -> None:
    ledger.token_cap = 500
    rendered = spend_summary()
    assert rendered["token_cap"] == 500
    assert rendered["usd_cap"] is None
