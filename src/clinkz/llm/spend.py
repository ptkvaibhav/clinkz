"""The engagement's LLM spend cap.

A bound on what a run may cost, enforced before a call rather than tallied
after it. The other two engagement bounds already exist — the governor's
request-rate ceiling and the :class:`~clinkz.models.engagement.EngagementWindow`
hard stop — and this is the third: an autonomous system with no wall between it
and a metered API has a bound only as long as nothing loops.

Two currencies, and the distinction is the whole design
-------------------------------------------------------

**Tokens are measured.** Every provider reports what a call consumed, so a
token cap is exact and needs nothing declared. It is always enforceable.

**Dollars are derived.** Converting tokens to money needs a per-model rate, and
a rate is a fact about somebody's price list on a particular day — not
something this module can know. So the price table starts **empty**, and a USD
cap with no declared rate for a model in the chain is a **refusal at startup**,
not a guess:

    CLINKZ_LLM_PRICES='{"claude-sonnet-5": {"input": 3.0, "output": 15.0}}'

Rates are USD per million tokens, declared by the operator against their own
current rate card. A default table would be worse than none: it would be right
on the day it was written, silently wrong afterwards, and the number it
produced would be reported as "actual API spend" with a confidence nothing
earned. A cap that quietly stops enforcing is indistinguishable from no cap.

The refusal is a HALT, not an exception. A cap that fires by raising through
twenty layers of methodology code lands in one of their ``except`` blocks and
becomes "that probe failed"; the governor's halt winds the phases down
cooperatively and the report is still produced. That matters most exactly when
the cap fires, because the operator needs to see what the run bought before it
stopped.

Absent by default, like the governor and the ledger.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

#: Governor halt reason recorded when the cap trips.
HALT_SPEND_CAP = "spend_cap"

#: Tokens per unit of a declared rate. Rate cards are quoted per million.
_TOKENS_PER_RATE_UNIT = 1_000_000


class SpendCapError(RuntimeError):
    """A USD cap was requested that cannot be enforced honestly."""


@dataclass(frozen=True)
class ModelPrice:
    """USD per million tokens for one model, as declared by the operator."""

    input_usd_per_mtok: float
    output_usd_per_mtok: float

    def cost(self, input_tokens: int, output_tokens: int) -> float:
        return (
            input_tokens * self.input_usd_per_mtok + output_tokens * self.output_usd_per_mtok
        ) / _TOKENS_PER_RATE_UNIT


def load_price_table(raw: str | None = None) -> dict[str, ModelPrice]:
    """Parse the operator's declared rate card.

    Args:
        raw: JSON of ``{model: {"input": x, "output": y}}`` in USD per million
            tokens. Defaults to ``CLINKZ_LLM_PRICES``.

    Returns:
        Model → price. Empty when nothing is declared, which is the honest
        default: see the module docstring.

    Raises:
        SpendCapError: The JSON is unparseable or an entry is malformed. A
            half-read price table would under-count silently.
    """
    text = (os.environ.get("CLINKZ_LLM_PRICES", "") if raw is None else raw).strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SpendCapError(f"CLINKZ_LLM_PRICES is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SpendCapError("CLINKZ_LLM_PRICES must be an object keyed by model name")

    table: dict[str, ModelPrice] = {}
    for model, entry in parsed.items():
        if not isinstance(entry, dict) or "input" not in entry or "output" not in entry:
            raise SpendCapError(
                f"price entry for {model!r} must be {{'input': <usd/Mtok>, 'output': <usd/Mtok>}}"
            )
        try:
            table[str(model)] = ModelPrice(
                input_usd_per_mtok=float(entry["input"]),
                output_usd_per_mtok=float(entry["output"]),
            )
        except (TypeError, ValueError) as exc:
            raise SpendCapError(f"price entry for {model!r} is not numeric: {exc}") from exc
    return table


@dataclass
class SpendLedger:
    """What this run has consumed, and the caps it may not cross.

    Attributes:
        token_cap: Total tokens (input + output) the run may consume. ``0``
            disables it.
        usd_cap: Total USD the run may spend. ``0`` disables it. Requires a
            declared price for every model that actually runs.
        prices: The operator's rate card.
    """

    token_cap: int = 0
    usd_cap: float = 0.0
    prices: dict[str, ModelPrice] = field(default_factory=dict)

    _input_tokens: int = 0
    _output_tokens: int = 0
    _usd: float = 0.0
    _unpriced_models: set[str] = field(default_factory=set)
    _by_model: dict[str, dict[str, float]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # -- accounting ---------------------------------------------------------

    def record(self, *, model: str, input_tokens: int, output_tokens: int) -> None:
        """Fold one served call into the totals."""
        price = self.prices.get(model)
        with self._lock:
            self._input_tokens += max(0, input_tokens)
            self._output_tokens += max(0, output_tokens)
            row = self._by_model.setdefault(
                model, {"input_tokens": 0, "output_tokens": 0, "usd": 0.0, "calls": 0}
            )
            row["input_tokens"] += max(0, input_tokens)
            row["output_tokens"] += max(0, output_tokens)
            row["calls"] += 1
            if price is None:
                # Recorded, never estimated. An unpriced model makes the USD
                # total a LOWER BOUND, and the report has to say so rather than
                # print a number that looks complete.
                self._unpriced_models.add(model)
            else:
                cost = price.cost(max(0, input_tokens), max(0, output_tokens))
                self._usd += cost
                row["usd"] += cost

    @property
    def total_tokens(self) -> int:
        with self._lock:
            return self._input_tokens + self._output_tokens

    @property
    def usd_spent(self) -> float:
        """USD accounted for. A **lower bound** when any model was unpriced."""
        with self._lock:
            return self._usd

    @property
    def usd_is_complete(self) -> bool:
        """Whether every model that ran had a declared price."""
        with self._lock:
            return not self._unpriced_models

    # -- enforcement --------------------------------------------------------

    def exceeded(self) -> str:
        """The cap that has been crossed, or ``""``.

        Checked BEFORE a call, so the run stops at the cap rather than one
        unbounded call past it.
        """
        if self.token_cap and self.total_tokens >= self.token_cap:
            return f"token cap reached: {self.total_tokens:,} of {self.token_cap:,} tokens consumed"
        if self.usd_cap and self.usd_spent >= self.usd_cap:
            return f"spend cap reached: ${self.usd_spent:.4f} of ${self.usd_cap:.2f}"
        return ""

    def assert_enforceable(self, models: list[str]) -> None:
        """Refuse a USD cap that cannot be enforced over *models*.

        Args:
            models: Every model that could serve a call this run.

        Raises:
            SpendCapError: A USD cap is set and some model has no declared
                price. Refused at startup rather than discovered as an
                under-count at the end — a cap that silently stops counting is
                indistinguishable from no cap at all.
        """
        if not self.usd_cap:
            return
        missing = sorted({m for m in models if m and m not in self.prices})
        if not missing:
            return
        raise SpendCapError(
            f"--spend-cap-usd is set but no price is declared for: {', '.join(missing)}. "
            "A dollar cap needs a rate per model, and clinkz ships no default rate "
            "card on purpose: a built-in table would be correct the day it was "
            "written, wrong afterwards, and would report a guess as actual spend. "
            "Declare your current rates:\n\n"
            '  CLINKZ_LLM_PRICES=\'{"<model>": {"input": <usd/Mtok>, '
            '"output": <usd/Mtok>}}\'\n\n'
            "Or use --token-cap, which is measured and needs no rate card."
        )

    # -- reporting ----------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        """Render for the run summary and the report."""
        with self._lock:
            by_model = {
                model: {
                    "calls": int(row["calls"]),
                    "input_tokens": int(row["input_tokens"]),
                    "output_tokens": int(row["output_tokens"]),
                    "usd": round(row["usd"], 6) if model in self.prices else None,
                }
                for model, row in sorted(self._by_model.items())
            }
            unpriced = sorted(self._unpriced_models)
            usd = self._usd
            tokens = self._input_tokens + self._output_tokens
            input_tokens = self._input_tokens
            output_tokens = self._output_tokens
        return {
            "token_cap": self.token_cap or None,
            "usd_cap": self.usd_cap or None,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": tokens,
            "usd_spent": round(usd, 6),
            "usd_is_complete": not unpriced,
            "unpriced_models": unpriced,
            "by_model": by_model,
        }

    def describe(self) -> str:
        """One line for the startup/teardown log."""
        caps = []
        caps.append(f"{self.token_cap:,} tokens" if self.token_cap else "no token cap")
        caps.append(f"${self.usd_cap:.2f}" if self.usd_cap else "no USD cap")
        spent = f"{self.total_tokens:,} tokens"
        if self.usd_cap or self.prices:
            qualifier = "" if self.usd_is_complete else " (lower bound — unpriced models ran)"
            spent += f", ${self.usd_spent:.4f}{qualifier}"
        return f"caps: {' / '.join(caps)}; consumed: {spent}"


# ---------------------------------------------------------------------------
# The active ledger — absent by default
# ---------------------------------------------------------------------------

_active_ledger: SpendLedger | None = None


def set_active_spend_ledger(ledger: SpendLedger | None) -> None:
    """Install (or clear) the run's spend ledger."""
    global _active_ledger
    _active_ledger = ledger


def get_active_spend_ledger() -> SpendLedger | None:
    """The run's spend ledger, or ``None`` when nothing installed one."""
    return _active_ledger


def record_spend(*, model: str, input_tokens: int, output_tokens: int) -> None:
    """Fold one call into the active ledger, if there is one."""
    ledger = _active_ledger
    if ledger is None:
        return
    ledger.record(model=model, input_tokens=input_tokens, output_tokens=output_tokens)


def spend_cap_exceeded() -> str:
    """The cap that has been crossed, or ``""`` (including when none is installed)."""
    ledger = _active_ledger
    if ledger is None:
        return ""
    return ledger.exceeded()


def spend_summary() -> dict[str, Any]:
    """The active ledger's summary, or the empty shape."""
    ledger = _active_ledger
    if ledger is None:
        return SpendLedger().summary()
    return ledger.summary()


__all__ = [
    "HALT_SPEND_CAP",
    "ModelPrice",
    "SpendCapError",
    "SpendLedger",
    "get_active_spend_ledger",
    "load_price_table",
    "record_spend",
    "set_active_spend_ledger",
    "spend_cap_exceeded",
    "spend_summary",
]
