"""The structural exfil guardrail (§P6.7.4) — the P6 safety proof.

These tests assert the guardrail is **structural, not convention**: the carrier
(:func:`build_oob_payload`) is *incapable* of interpolating target / LLM / source
data into the callback host. It has no parameter through which such data could
ride, and it rejects any nonce or zone that is not shape-valid — so an exfil
template like ``${env:AWS_SECRET}.<nonce>`` or a subdomain-encoded file byte is not
a payload the carrier can be asked to build. If any of these fail, the OOB channel
could become an exfil channel and the primitive must not ship.
"""

from __future__ import annotations

import inspect

import pytest

from clinkz.oob.templates import (
    CallbackShape,
    OOBTemplateId,
    build_oob_payload,
    is_valid_nonce,
    mint_nonce,
)

ZONE = "oob.clinkz.test"


# ---------------------------------------------------------------------------
# The nonce is opaque, metacharacter-free, and unforgeable
# ---------------------------------------------------------------------------


def test_minted_nonce_is_metacharacter_free() -> None:
    """Every minted nonce is strictly [a-z0-9] — no dot/slash/${/interpolation."""
    for _ in range(200):
        nonce = mint_nonce()
        assert is_valid_nonce(nonce), nonce
        # Explicitly: none of the characters that could break out of a host label.
        for bad in (".", "/", "$", "{", "}", ":", "@", "%", " ", "\\", "-"):
            assert bad not in nonce


def test_minted_nonces_are_unique() -> None:
    """Fresh nonces do not collide — the unforgeability precondition (§P6.2.2)."""
    seen = {mint_nonce() for _ in range(1000)}
    assert len(seen) == 1000


# ---------------------------------------------------------------------------
# The carrier interpolates ONLY the nonce — target data is structurally excluded
# ---------------------------------------------------------------------------


def test_carrier_has_no_target_data_parameter() -> None:
    """build_oob_payload's signature has NO slot for target/LLM/source data.

    The structural guarantee: a caller literally cannot pass observed content — the
    only inputs are a template id (an enum), a nonce, a zone, and a shape.
    """
    params = set(inspect.signature(build_oob_payload).parameters)
    assert params == {"template_id", "nonce", "zone", "shape"}


def test_carrier_builds_only_from_nonce_and_zone() -> None:
    """A well-formed callback URL contains exactly the nonce + zone, nothing else."""
    nonce = mint_nonce()
    url = build_oob_payload(
        OOBTemplateId.BLIND_SSRF_URL, nonce, ZONE, shape=CallbackShape.SUBDOMAIN
    )
    assert url == f"http://{nonce}.{ZONE}/"


@pytest.mark.parametrize(
    "exfil_attempt",
    [
        "${env:AWS_SECRET_ACCESS_KEY}",  # env-var lookup exfil
        "${jndi:ldap://evil}",  # JNDI exfil
        "cat-etc-passwd",  # a subdomain-encoded file name (has a dash → invalid)
        "../../etc/passwd",  # path traversal
        "evil.example.com",  # an attacker host (has dots)
        "aGVsbG8=",  # base64 (has '=' padding / uppercase)
        "victim.internal",  # target-derived host
        "",  # empty
        "a b",  # whitespace
        "abc",  # too short (< 16)
    ],
)
def test_carrier_refuses_non_nonce_data(exfil_attempt: str) -> None:
    """A 'nonce' carrying target data / metacharacters is REFUSED (ValueError).

    This is the load-bearing structural assertion: exfil templates are impossible
    to emit because the only interpolation slot rejects anything that is not a
    shape-valid nonce.
    """
    with pytest.raises(ValueError):
        build_oob_payload(
            OOBTemplateId.BLIND_SSRF_URL, exfil_attempt, ZONE, shape=CallbackShape.SUBDOMAIN
        )


@pytest.mark.parametrize(
    "hostile_zone",
    [
        "evil.com/../etc",  # path in the zone
        "zone.test/@evil.com",  # userinfo smuggling
        "zone.test ",  # trailing space
        "zone.test\nHost: evil",  # header injection
        "${env:X}.zone",  # interpolation
        "zone.test:99999999",  # absurd port
    ],
)
def test_carrier_refuses_malformed_zone(hostile_zone: str) -> None:
    """A zone that is not a bare host[:port] is REFUSED — no path/userinfo/CRLF."""
    nonce = mint_nonce()
    with pytest.raises(ValueError):
        build_oob_payload(
            OOBTemplateId.BLIND_SSRF_URL, nonce, hostile_zone, shape=CallbackShape.PATH
        )


def test_subdomain_shape_places_nonce_as_leftmost_label() -> None:
    nonce = mint_nonce()
    url = build_oob_payload(
        OOBTemplateId.BLIND_SSRF_URL, nonce, ZONE, shape=CallbackShape.SUBDOMAIN
    )
    host = url.split("://", 1)[1].split("/", 1)[0]
    assert host.split(".", 1)[0] == nonce
    assert host.endswith(ZONE)


def test_path_shape_uses_fixed_authority_with_nonce_in_path() -> None:
    """PATH shape: the host is the fixed authority (zero variable), nonce in path.

    The strongest form of the guardrail — the callback host has no variable at all.
    """
    nonce = mint_nonce()
    authority = "172.20.0.1:18080"
    url = build_oob_payload(
        OOBTemplateId.BLIND_SSRF_URL, nonce, authority, shape=CallbackShape.PATH
    )
    assert url == f"http://{authority}/{nonce}"


def test_jndi_template_is_payload_free_lookup_only() -> None:
    """The JNDI template is a bare lookup (no gadget), carrying only the nonce."""
    nonce = mint_nonce()
    payload = build_oob_payload(OOBTemplateId.JNDI_LDAP, nonce, ZONE, shape=CallbackShape.SUBDOMAIN)
    assert payload == f"${{jndi:ldap://{nonce}.{ZONE}/x}}"
    # No second-stage class / gadget reference — confirmation is the lookup egress.
    assert "class" not in payload.lower()


def test_dns_template_requires_subdomain_shape() -> None:
    """A bare DNS callback needs the subdomain shape (no path leg for DNS)."""
    nonce = mint_nonce()
    assert (
        build_oob_payload(OOBTemplateId.DNS_LOOKUP, nonce, ZONE, shape=CallbackShape.SUBDOMAIN)
        == f"{nonce}.{ZONE}"
    )
    with pytest.raises(ValueError):
        build_oob_payload(OOBTemplateId.DNS_LOOKUP, nonce, ZONE, shape=CallbackShape.PATH)
