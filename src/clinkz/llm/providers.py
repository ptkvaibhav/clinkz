"""Provider auto-detection from the environment.

Convention: ``<PROVIDER>_API_KEY``, plus an optional ``<PROVIDER>_MODEL`` with a
documented default. Clinkz discovers what is present, registers every key for
redaction, validates each one with a cheap call, and reports which passed.

Three rules, and the first is the one that matters
--------------------------------------------------

**A detected key makes a provider AVAILABLE. It does not give it a position.**
Priority is declared in :attr:`clinkz.config.Settings.llm_provider_priority`
with Anthropic pinned first, and nothing in this module writes to it. Enrolling
a discovered key into the chain is how a run gets a surprise model swap: an
operator adds ``FOO_API_KEY`` for one experiment on a Tuesday, and the next
engagement's exploit plan is written by whatever it belonged to. The
availability set and the priority order answer different questions — "could
this provider be reached" and "should it be" — and only the second is a
decision.

**A dead key is discovered at startup, not mid-engagement.** Each detected key
gets one cheap call before any agent runs. The worst time to learn a key was
revoked is after recon has finished and the exploit phase is holding a plan.
Validation is reported per key and does not by itself abort the run: a
provider that is merely unreachable right now is a different fact from a key
that was refused, and only the primary being unusable is fatal.

**Every detected key is registered with the redaction chokepoint on intake.**
The way the lab password was, and *in addition to* the shape rules rather than
instead of them — the relationship is worth stating precisely, because the
obvious version of this claim is wrong.

``engagement/credential_shapes.py::API_KEY_RES`` does recognise the three
vendors it was written for: ``sk-ant-…``, ``AIza…`` and ``sk-…`` are redacted
to a vendor-tagged fingerprint whether or not anything is registered. What it
cannot recognise is a key that does not match one of those literals — a
self-hosted gateway, a corporate proxy credential, a fourth provider added to
:data:`KNOWN_PROVIDERS` before anyone remembers to add its prefix to the shape
table. Those are an unremarkable run of characters, which is also what a
session id, a nonce, a hash prefix and half the evidence in a real finding look
like, so no shape rule can be written that catches them without shredding
evidence.

So the shape table is a floor that depends on staying in sync with reality, and
intake registration is what makes the guarantee independent of that: it matches
the exact value, it covers every variable including the aliases, and it does
not care whether anyone updated a regex. It has to happen here because this is
the only code that reads the values.

Absent a key entirely, :func:`detect_providers` finds nothing and
:func:`assert_any_provider_available` raises with the expected variables named.
That is the first thing a new user hits, so it says what to set rather than
what went wrong.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from clinkz.config import GEMINI_PINNED_MODEL, Settings
from clinkz.config import settings as global_settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProviderSpec:
    """How one provider's credentials and model are named in the environment.

    Attributes:
        name: The provider id used everywhere else (``anthropic``, ...).
        key_env: The conventional ``<PROVIDER>_API_KEY`` variable.
        alt_key_envs: Historical aliases still honoured. ``GOOGLE_API_KEY`` is
            the only one; it predates the convention and is read second.
        model_env: The conventional ``<PROVIDER>_MODEL`` variable.
        default_model: What the provider runs when ``model_env`` is unset. A
            documented default per provider, because "whatever the SDK picks"
            is a floating alias by another name.
        settings_field: The ``Settings`` field holding the resolved model, so
            the detected model is read from the same place the client will.
    """

    name: str
    key_env: str
    model_env: str
    default_model: str
    settings_field: str
    alt_key_envs: tuple[str, ...] = ()

    def key_envs(self) -> tuple[str, ...]:
        """Every variable that may carry this provider's key, in read order."""
        return (self.key_env, *self.alt_key_envs)


#: The providers clinkz knows how to talk to. Ollama is absent on purpose: the
#: client is a stub, it takes no key, and listing it would put a provider that
#: cannot serve a call into the "available" set.
KNOWN_PROVIDERS: tuple[ProviderSpec, ...] = (
    ProviderSpec(
        name="anthropic",
        key_env="ANTHROPIC_API_KEY",
        model_env="ANTHROPIC_MODEL",
        default_model="claude-sonnet-5",
        settings_field="anthropic_model",
    ),
    ProviderSpec(
        name="gemini",
        key_env="GEMINI_API_KEY",
        model_env="GEMINI_MODEL",
        default_model=GEMINI_PINNED_MODEL,
        settings_field="gemini_model",
        alt_key_envs=("GOOGLE_API_KEY",),
    ),
    ProviderSpec(
        name="openai",
        key_env="OPENAI_API_KEY",
        model_env="OPENAI_MODEL",
        default_model="gpt-4o-mini",
        settings_field="agent_model",
    ),
)

#: Indexed by name, for callers that have a provider id in hand.
PROVIDER_SPECS: dict[str, ProviderSpec] = {spec.name: spec for spec in KNOWN_PROVIDERS}


class NoProviderKeyError(RuntimeError):
    """Not one provider key is present in the environment."""


class KeyStatus(StrEnum):
    """What a startup validation call proved about a key.

    ``INVALID`` and ``UNREACHABLE`` are held apart because they have different
    fixes and different consequences. A refused key is the operator's to
    correct; a 503 is the provider having a minute and says nothing about the
    credential.
    """

    #: The provider answered. The key works.
    VALID = "valid"
    #: The provider refused on an account condition — revoked, unpaid, wrong key.
    INVALID = "invalid"
    #: Rate-limited, overloaded or timed out. Not a verdict on the key.
    UNREACHABLE = "unreachable"
    #: Something else went wrong. Reported rather than guessed at.
    UNKNOWN = "unknown"
    #: Validation was switched off.
    NOT_CHECKED = "not_checked"


@dataclass(frozen=True)
class DetectedProvider:
    """A provider whose key was found in the environment.

    Carries no key material and never will — the value goes straight to the
    redaction registry and is not retained on this object. ``key_env`` names
    *where* the key was found, which is what an operator needs to fix it.
    """

    name: str
    key_env: str
    model: str
    model_from_env: bool
    key_length: int

    def describe(self) -> str:
        """One line for the startup report. Names the variable, never the value."""
        source = "env" if self.model_from_env else "default"
        return f"{self.name}: key from {self.key_env}, model {self.model} ({source})"


@dataclass(frozen=True)
class KeyValidation:
    """The result of one cheap startup call against one detected key."""

    provider: str
    status: KeyStatus
    detail: str = ""

    @property
    def passed(self) -> bool:
        return self.status is KeyStatus.VALID

    def describe(self) -> str:
        tail = f" — {self.detail}" if self.detail else ""
        return f"{self.provider}: {self.status.value}{tail}"


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def detect_providers(
    env: Mapping[str, str] | None = None,
    config: Settings | None = None,
) -> list[DetectedProvider]:
    """Find every provider with a key in *env*.

    Args:
        env: Environment mapping. Defaults to ``os.environ``.
        config: Settings, consulted for the resolved model so the detected
            model matches what the client will actually send.

    Returns:
        One entry per provider with a non-empty key, in
        :data:`KNOWN_PROVIDERS` order. **That order is not a priority** — it is
        the order they are listed in, and the caller must not read it as one.
    """
    environ = os.environ if env is None else env
    cfg = config or global_settings
    found: list[DetectedProvider] = []
    for spec in KNOWN_PROVIDERS:
        key = ""
        key_env = ""
        for candidate in spec.key_envs():
            value = (environ.get(candidate) or "").strip()
            if value:
                key, key_env = value, candidate
                break
        if not key:
            continue
        model_from_env = bool((environ.get(spec.model_env) or "").strip())
        model = getattr(cfg, spec.settings_field, "") or spec.default_model
        found.append(
            DetectedProvider(
                name=spec.name,
                key_env=key_env,
                model=model,
                model_from_env=model_from_env,
                key_length=len(key),
            )
        )
    return found


def register_detected_keys(env: Mapping[str, str] | None = None) -> int:
    """Register every provider key for redaction, on intake.

    The third intake route, alongside operator-supplied credentials and the
    hardcoded lab password. A key is registered from **every** variable that
    holds one, including the aliases: ``GOOGLE_API_KEY`` and ``GEMINI_API_KEY``
    may hold different values, and redacting only the one the detector chose
    would leave the other in whatever artifact quoted it.

    Returns:
        How many distinct key values were registered. Never the values, and
        never how long they were — a length is a search-space reduction.
    """
    from clinkz.engagement.secrets import register_secret

    environ = os.environ if env is None else env
    registered = 0
    for spec in KNOWN_PROVIDERS:
        for candidate in spec.key_envs():
            value = (environ.get(candidate) or "").strip()
            if value and register_secret(value):
                registered += 1
    if registered:
        logger.info(
            "Registered %d provider API key(s) for redaction. A key has no "
            "distinctive shape, so intake registration is the only thing that "
            "keeps it out of an artifact.",
            registered,
        )
    return registered


def assert_any_provider_available(env: Mapping[str, str] | None = None) -> None:
    """Fail at startup when not one provider key is set.

    Raises:
        NoProviderKeyError: Nothing was detected. The message names the
            variables rather than describing the failure, because this is the
            first thing a new user hits and "what do I set" is the only
            question they have.
    """
    if detect_providers(env):
        return
    expected = "\n".join(
        f"  {spec.key_env:<20} (optional: {spec.model_env}, default {spec.default_model})"
        for spec in KNOWN_PROVIDERS
    )
    raise NoProviderKeyError(
        "No LLM provider API key found in the environment. Clinkz cannot run "
        "without one.\n\nSet at least one of these in your .env (see "
        ".env.example):\n\n"
        f"{expected}\n\n"
        "ANTHROPIC_API_KEY is the one that matters: Anthropic is priority 1 for "
        "every call on every phase. The others are fallback only, and a fallback "
        "is a disqualifying event, not a preference."
    )


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _classify(exc: BaseException) -> KeyValidation | None:
    """Map a probe exception onto a status, or ``None`` if it is not ours."""
    from clinkz.llm.base import (
        LLMTimeoutError,
        LLMUnavailableError,
        ProviderAccountError,
        RateLimitError,
        ServiceUnavailableError,
    )

    if isinstance(exc, ProviderAccountError):
        return KeyValidation("", KeyStatus.INVALID, str(exc)[:200])
    if isinstance(exc, RateLimitError | ServiceUnavailableError | LLMTimeoutError):
        return KeyValidation("", KeyStatus.UNREACHABLE, type(exc).__name__)
    if isinstance(exc, LLMUnavailableError):
        return KeyValidation("", KeyStatus.UNREACHABLE, type(exc).__name__)
    return None


#: Error text that means the credential was refused, whichever provider said
#: it. Kept beside the Anthropic client's own markers rather than imported from
#: it: that list exists to decide whether to disable a provider mid-run, and
#: widening it for a startup probe would change a live-engagement behaviour to
#: improve a diagnostic.
_AUTH_REFUSAL_MARKERS: tuple[str, ...] = (
    "invalid x-api-key",
    "authentication_error",
    "permission_error",
    "api key not valid",
    "invalid api key",
    "incorrect api key",
    "unauthorized",
    "401",
    "403",
)


async def validate_provider_key(
    provider: str,
    config: Settings | None = None,
    *,
    timeout: float = 30.0,
) -> KeyValidation:
    """Spend one cheap call proving whether *provider*'s key works.

    Args:
        provider: Provider id.
        config: Settings override.
        timeout: Wall-clock ceiling for the probe. A startup check that can
            hang is a startup check that gets removed.

    Returns:
        A :class:`KeyValidation`. Never raises: a validation step that can end
        the process on a transient network fault is worse than the dead key it
        exists to find.
    """
    from clinkz.llm.factory import get_llm_client

    cfg = config or global_settings
    spec = PROVIDER_SPECS.get(provider)
    model = getattr(cfg, spec.settings_field, None) if spec else None

    try:
        client = get_llm_client(provider, model=model)
    except Exception as exc:  # noqa: BLE001 — a missing SDK is a status, not a crash
        return KeyValidation(provider, KeyStatus.UNKNOWN, f"could not construct: {exc}"[:200])

    try:
        await asyncio.wait_for(client.generate_text("ping"), timeout=timeout)
        return KeyValidation(provider, KeyStatus.VALID)
    except TimeoutError:
        return KeyValidation(provider, KeyStatus.UNREACHABLE, f"probe exceeded {timeout:g}s")
    except Exception as exc:  # noqa: BLE001 — every outcome is a status
        classified = _classify(exc)
        if classified is not None:
            return KeyValidation(provider, classified.status, classified.detail)
        text = str(exc).lower()
        if any(marker in text for marker in _AUTH_REFUSAL_MARKERS):
            return KeyValidation(provider, KeyStatus.INVALID, str(exc)[:200])
        return KeyValidation(provider, KeyStatus.UNKNOWN, f"{type(exc).__name__}: {exc}"[:200])


async def validate_detected_keys(
    detected: list[DetectedProvider] | None = None,
    config: Settings | None = None,
    *,
    enabled: bool = True,
) -> list[KeyValidation]:
    """Validate every detected key, concurrently.

    Args:
        detected: Providers to check. Defaults to a fresh detection.
        config: Settings override.
        enabled: When ``False``, every key is reported ``NOT_CHECKED`` rather
            than silently assumed good — an unrun check and a passed check must
            not look the same in the startup report.

    Returns:
        One result per detected provider, in the order given.
    """
    providers = detect_providers(config=config) if detected is None else detected
    if not enabled:
        return [
            KeyValidation(p.name, KeyStatus.NOT_CHECKED, "validation disabled") for p in providers
        ]
    results = await asyncio.gather(
        *(validate_provider_key(p.name, config) for p in providers),
        return_exceptions=True,
    )
    out: list[KeyValidation] = []
    for provider, result in zip(providers, results, strict=True):
        if isinstance(result, KeyValidation):
            out.append(result)
        else:
            out.append(KeyValidation(provider.name, KeyStatus.UNKNOWN, repr(result)[:200]))
    return out


# ---------------------------------------------------------------------------
# The startup step
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProviderPreflight:
    """What startup detection found, validated, and declared."""

    detected: list[DetectedProvider]
    validations: list[KeyValidation]
    priority: tuple[str, ...]
    keys_registered: int

    @property
    def available(self) -> frozenset[str]:
        """Providers with a key. Availability, never priority."""
        return frozenset(p.name for p in self.detected)

    @property
    def primary(self) -> str:
        """The declared priority-1 provider."""
        return self.priority[0] if self.priority else ""

    @property
    def primary_usable(self) -> bool:
        """Whether the priority-1 provider has a key that was not refused.

        ``UNREACHABLE`` counts as usable: the provider was busy, and the chain
        retries. Only an outright refusal says the credential is wrong.
        """
        if self.primary not in self.available:
            return False
        for validation in self.validations:
            if validation.provider == self.primary:
                return validation.status is not KeyStatus.INVALID
        return True

    def to_dict(self) -> dict[str, Any]:
        """Render for the run summary. Carries no key material."""
        return {
            "declared_priority": list(self.priority),
            "available": sorted(self.available),
            "primary": self.primary,
            "primary_usable": self.primary_usable,
            "keys_registered_for_redaction": self.keys_registered,
            "detected": [
                {
                    "provider": p.name,
                    "key_env": p.key_env,
                    "model": p.model,
                    "model_source": "env" if p.model_from_env else "default",
                }
                for p in self.detected
            ],
            "validation": [
                {"provider": v.provider, "status": v.status.value, "detail": v.detail}
                for v in self.validations
            ],
        }

    def log_summary(self, log: logging.Logger) -> None:
        """Report what was detected and what passed."""
        log.info("Provider priority (declared, not detected): %s", " → ".join(self.priority))
        for provider in self.detected:
            log.info("  detected %s", provider.describe())
        for validation in self.validations:
            level = logging.INFO if validation.passed else logging.WARNING
            log.log(level, "  validated %s", validation.describe())
        unused = sorted(self.available - set(self.priority))
        if unused:
            log.info(
                "  available but NOT in the chain: %s. A detected key makes a "
                "provider available; it does not give it a position.",
                ", ".join(unused),
            )


async def preflight_providers(
    config: Settings | None = None,
    *,
    validate: bool | None = None,
    env: Mapping[str, str] | None = None,
) -> ProviderPreflight:
    """Detect, register for redaction, validate, and report. Run once at startup.

    Order matters and is not arbitrary. Registration happens **before**
    validation, so that if a probe raises an exception quoting the key back —
    which some SDKs do — the redactor already knows the value.

    Args:
        config: Settings override.
        validate: Whether to spend a cheap call per key. Defaults to the
            ``CLINKZ_VALIDATE_KEYS`` environment variable (on unless set to a
            falsey string).
        env: Environment mapping override, for tests.

    Returns:
        The preflight report.

    Raises:
        NoProviderKeyError: Not one key was found.
    """
    keys_registered = register_detected_keys(env)
    assert_any_provider_available(env)

    cfg = config or global_settings
    detected = detect_providers(env, cfg)

    if validate is None:
        raw = (os.environ.get("CLINKZ_VALIDATE_KEYS") or "").strip().lower()
        validate = raw not in ("0", "false", "no", "off")

    validations = await validate_detected_keys(detected, cfg, enabled=validate)
    return ProviderPreflight(
        detected=detected,
        validations=validations,
        priority=tuple(cfg.llm_provider_priority),
        keys_registered=keys_registered,
    )


__all__ = [
    "KNOWN_PROVIDERS",
    "PROVIDER_SPECS",
    "DetectedProvider",
    "KeyStatus",
    "KeyValidation",
    "NoProviderKeyError",
    "ProviderPreflight",
    "ProviderSpec",
    "assert_any_provider_available",
    "detect_providers",
    "preflight_providers",
    "register_detected_keys",
    "validate_detected_keys",
    "validate_provider_key",
]
