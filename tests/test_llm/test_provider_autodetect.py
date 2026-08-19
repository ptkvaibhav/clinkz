"""Provider auto-detection from the environment (Part C).

The rule with teeth is the second one: a detected key makes a provider
AVAILABLE and does not give it a position. Auto-enrolling a discovered key into
the chain is how a run gets a surprise model swap.
"""

from __future__ import annotations

import pytest

from clinkz.config import GEMINI_PINNED_MODEL, Settings
from clinkz.engagement.secrets import clear_secrets, redact, registered_secret_count
from clinkz.llm.providers import (
    KNOWN_PROVIDERS,
    DetectedProvider,
    KeyStatus,
    KeyValidation,
    NoProviderKeyError,
    ProviderPreflight,
    assert_any_provider_available,
    detect_providers,
    preflight_providers,
    register_detected_keys,
    validate_detected_keys,
)

# Assembled rather than written out. These match the vendor regexes in
# credential_shapes.py at runtime, which is the point of the tests below — and
# a literal that matches those regexes is exactly what the pre-commit secret
# guard refuses to let into the tree, correctly and without caring that this
# one is fake.
ANTHROPIC_KEY = "sk-" + "ant-" + "a" * 32
GEMINI_KEY = "AI" + "za" + "B" * 35
OPENAI_KEY = "sk-" + "C" * 32


@pytest.fixture(autouse=True)
def _clean_secret_registry():
    clear_secrets()
    yield
    clear_secrets()


# ---------------------------------------------------------------------------
# The convention
# ---------------------------------------------------------------------------


def test_every_known_provider_follows_the_naming_convention() -> None:
    for spec in KNOWN_PROVIDERS:
        assert spec.key_env == f"{spec.name.upper()}_API_KEY"
        assert spec.model_env == f"{spec.name.upper()}_MODEL"


def test_every_known_provider_documents_a_default_model() -> None:
    """ "Whatever the SDK picks" is a floating alias by another name."""
    for spec in KNOWN_PROVIDERS:
        assert spec.default_model, spec.name
        assert not spec.default_model.endswith("-latest"), spec.name


def test_ollama_is_not_listed_as_available() -> None:
    """The client is a stub; listing it would put a non-server in the set."""
    assert "ollama" not in {spec.name for spec in KNOWN_PROVIDERS}


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def test_detects_each_provider_from_its_key_variable() -> None:
    env = {
        "ANTHROPIC_API_KEY": ANTHROPIC_KEY,
        "GEMINI_API_KEY": GEMINI_KEY,
        "OPENAI_API_KEY": OPENAI_KEY,
    }
    assert [d.name for d in detect_providers(env)] == ["anthropic", "gemini", "openai"]


def test_an_absent_or_blank_key_is_not_a_detection() -> None:
    assert detect_providers({"ANTHROPIC_API_KEY": "   "}) == []
    assert detect_providers({}) == []


def test_the_legacy_google_alias_is_honoured_second() -> None:
    detected = detect_providers({"GOOGLE_API_KEY": GEMINI_KEY})
    assert [d.name for d in detected] == ["gemini"]
    assert detected[0].key_env == "GOOGLE_API_KEY"

    both = detect_providers({"GEMINI_API_KEY": GEMINI_KEY, "GOOGLE_API_KEY": "other"})
    assert both[0].key_env == "GEMINI_API_KEY", "the conventional name wins"


def test_a_detected_provider_carries_no_key_material() -> None:
    """The report renders this object; it must never be able to leak a key."""
    detected = detect_providers({"ANTHROPIC_API_KEY": ANTHROPIC_KEY})[0]
    assert ANTHROPIC_KEY not in repr(detected)
    assert ANTHROPIC_KEY not in detected.describe()
    assert "ANTHROPIC_API_KEY" in detected.describe(), "names WHERE, not what"


def test_the_model_comes_from_the_env_when_set_and_the_default_otherwise() -> None:
    cfg = Settings()
    detected = detect_providers({"GEMINI_API_KEY": GEMINI_KEY}, cfg)[0]
    assert detected.model == GEMINI_PINNED_MODEL
    assert detected.model_from_env is False

    with_env = detect_providers(
        {"GEMINI_API_KEY": GEMINI_KEY, "GEMINI_MODEL": GEMINI_PINNED_MODEL}, cfg
    )[0]
    assert with_env.model_from_env is True


# ---------------------------------------------------------------------------
# Availability is not priority
# ---------------------------------------------------------------------------


def test_detection_does_not_change_the_declared_priority() -> None:
    """The whole point. A key is availability; the chain order is a decision."""
    cfg = Settings()
    before = cfg.llm_provider_priority
    detect_providers({"OPENAI_API_KEY": OPENAI_KEY, "GEMINI_API_KEY": GEMINI_KEY}, cfg)
    assert cfg.llm_provider_priority == before
    assert before[0] == "anthropic"


@pytest.mark.asyncio
async def test_a_gemini_only_environment_still_declares_anthropic_first() -> None:
    """Availability says Gemini; priority still says Anthropic."""
    env = {"GEMINI_API_KEY": GEMINI_KEY}
    preflight = await preflight_providers(validate=False, env=env)
    assert preflight.available == {"gemini"}
    assert preflight.primary == "anthropic"
    assert preflight.primary_usable is False, "no anthropic key means the primary is unusable"


def test_the_preflight_reports_availability_apart_from_the_chain() -> None:
    preflight = ProviderPreflight(
        detected=[DetectedProvider("gemini", "GEMINI_API_KEY", "m", False, 10)],
        validations=[],
        priority=("anthropic", "openai"),
        keys_registered=1,
    )
    rendered = preflight.to_dict()
    assert rendered["declared_priority"] == ["anthropic", "openai"]
    assert rendered["available"] == ["gemini"]


# ---------------------------------------------------------------------------
# Keys are registered for redaction on intake
# ---------------------------------------------------------------------------


def test_every_detected_key_is_registered_for_redaction() -> None:
    env = {
        "ANTHROPIC_API_KEY": ANTHROPIC_KEY,
        "GEMINI_API_KEY": GEMINI_KEY,
        "OPENAI_API_KEY": OPENAI_KEY,
    }
    assert register_detected_keys(env) == 3
    assert registered_secret_count() == 3
    for key in (ANTHROPIC_KEY, GEMINI_KEY, OPENAI_KEY):
        assert key not in redact(f"traceback says the key was {key} oops")


def test_an_alias_holding_a_different_value_is_also_registered() -> None:
    """Redacting only the one the detector chose leaves the other in artifacts."""
    other = "AIzaDIFFERENTDIFFERENTDIFFERENTDIFFERENT"
    register_detected_keys({"GEMINI_API_KEY": GEMINI_KEY, "GOOGLE_API_KEY": other})
    assert registered_secret_count() == 2
    assert other not in redact(f"leaked {other}")


def test_the_known_vendor_shapes_are_already_covered_without_registration() -> None:
    """The floor. Stated so the next test's gap is legible as a gap."""
    for key in (ANTHROPIC_KEY, GEMINI_KEY, OPENAI_KEY):
        assert key not in redact(f"bare key {key}")


def test_a_key_matching_no_vendor_shape_is_caught_only_by_registration() -> None:
    """The gap the shape table structurally cannot close.

    A self-hosted gateway credential, a corporate proxy key, or a fourth
    provider added to KNOWN_PROVIDERS before anyone updates API_KEY_RES. It is
    an unremarkable run of characters — which is also what a nonce and half the
    evidence in a real finding look like — so no shape rule catches it without
    shredding evidence. Exact-value registration does.
    """
    unknown_vendor_key = "gw-live-01234567890abcdefghijklmnop"
    assert unknown_vendor_key in redact(f"bare key {unknown_vendor_key}")

    register_detected_keys({"ANTHROPIC_API_KEY": unknown_vendor_key})
    assert unknown_vendor_key not in redact(f"bare key {unknown_vendor_key}")


@pytest.mark.asyncio
async def test_registration_happens_before_validation() -> None:
    """A probe that quotes the key back must find the redactor already armed."""
    env = {"ANTHROPIC_API_KEY": ANTHROPIC_KEY}
    preflight = await preflight_providers(validate=False, env=env)
    assert preflight.keys_registered == 1
    assert ANTHROPIC_KEY not in redact(f"x {ANTHROPIC_KEY} y")


# ---------------------------------------------------------------------------
# No key at all
# ---------------------------------------------------------------------------


def test_no_key_at_all_names_every_expected_variable() -> None:
    with pytest.raises(NoProviderKeyError) as excinfo:
        assert_any_provider_available({})
    message = str(excinfo.value)
    for spec in KNOWN_PROVIDERS:
        assert spec.key_env in message
        assert spec.model_env in message
        assert spec.default_model in message
    assert ".env.example" in message


def test_one_key_is_enough_to_pass_the_startup_check() -> None:
    assert_any_provider_available({"OPENAI_API_KEY": OPENAI_KEY})


@pytest.mark.asyncio
async def test_preflight_raises_when_nothing_is_configured() -> None:
    with pytest.raises(NoProviderKeyError):
        await preflight_providers(validate=False, env={})


# ---------------------------------------------------------------------------
# Validation reports what passed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disabled_validation_is_not_the_same_as_passed() -> None:
    """An unrun check and a passed check must not look alike in the report."""
    detected = detect_providers({"ANTHROPIC_API_KEY": ANTHROPIC_KEY})
    results = await validate_detected_keys(detected, enabled=False)
    assert [r.status for r in results] == [KeyStatus.NOT_CHECKED]
    assert not results[0].passed


@pytest.mark.asyncio
async def test_a_refused_key_and_an_unreachable_provider_are_different(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Different fixes, so different statuses."""
    from clinkz.llm import providers as providers_mod
    from clinkz.llm.base import ProviderAccountError, ServiceUnavailableError

    class _Client:
        def __init__(self, exc: Exception) -> None:
            self._exc = exc

        async def generate_text(self, _prompt: str, **_kw: object) -> str:
            raise self._exc

    scripted: dict[str, Exception] = {
        "anthropic": ProviderAccountError("invalid x-api-key"),
        "gemini": ServiceUnavailableError("503 overloaded"),
    }
    monkeypatch.setattr(
        providers_mod,
        "detect_providers",
        lambda *a, **k: [
            DetectedProvider("anthropic", "ANTHROPIC_API_KEY", "m", False, 1),
            DetectedProvider("gemini", "GEMINI_API_KEY", "m", False, 1),
        ],
    )
    monkeypatch.setattr(
        "clinkz.llm.factory.get_llm_client",
        lambda provider=None, **kw: _Client(scripted[str(provider)]),
    )
    results = await validate_detected_keys()
    by_provider = {r.provider: r.status for r in results}
    assert by_provider["anthropic"] is KeyStatus.INVALID
    assert by_provider["gemini"] is KeyStatus.UNREACHABLE


@pytest.mark.asyncio
async def test_validation_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A startup check that can end the process on a network blip gets removed."""
    from clinkz.llm import providers as providers_mod

    monkeypatch.setattr(
        providers_mod,
        "detect_providers",
        lambda *a, **k: [DetectedProvider("anthropic", "ANTHROPIC_API_KEY", "m", False, 1)],
    )

    def _explode(**_kw: object):
        raise RuntimeError("socket exploded")

    monkeypatch.setattr("clinkz.llm.factory.get_llm_client", _explode)
    results = await validate_detected_keys()
    assert results[0].status in (KeyStatus.UNKNOWN, KeyStatus.UNREACHABLE)


def test_unreachable_does_not_condemn_the_primary() -> None:
    """A busy provider is not a wrong credential."""
    preflight = ProviderPreflight(
        detected=[DetectedProvider("anthropic", "ANTHROPIC_API_KEY", "m", False, 1)],
        validations=[KeyValidation("anthropic", KeyStatus.UNREACHABLE, "503")],
        priority=("anthropic",),
        keys_registered=1,
    )
    assert preflight.primary_usable is True


def test_a_refused_primary_is_reported_unusable() -> None:
    preflight = ProviderPreflight(
        detected=[DetectedProvider("anthropic", "ANTHROPIC_API_KEY", "m", False, 1)],
        validations=[KeyValidation("anthropic", KeyStatus.INVALID, "invalid x-api-key")],
        priority=("anthropic",),
        keys_registered=1,
    )
    assert preflight.primary_usable is False


def test_the_rendered_preflight_carries_no_key_material() -> None:
    preflight = ProviderPreflight(
        detected=[DetectedProvider("anthropic", "ANTHROPIC_API_KEY", "m", False, 42)],
        validations=[KeyValidation("anthropic", KeyStatus.VALID)],
        priority=("anthropic",),
        keys_registered=1,
    )
    rendered = repr(preflight.to_dict())
    assert "42" not in rendered, "a key length is a search-space reduction"
