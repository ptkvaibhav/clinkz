"""CLINKZ-OWNED out-of-band payload templates + the callback-URL carrier.

This module is the **structural exfil guardrail** the P6 design (§P6.1.5 guardrail
2, §P6.7.4) makes non-negotiable. It departs deliberately from the in-band
"LLM crafts the payload" pattern:

* A methodology / LLM **selects** an :class:`OOBTemplateId` (blind-SSRF-URL, JNDI,
  DNS). It **never authors the payload string** — there is no code path where a
  target-, LLM-, or source-derived string is formatted into an OOB payload.
* The **only** variable a template carries is a Clinkz-minted, opaque,
  metacharacter-free **nonce** (:func:`mint_nonce` → ``[a-z0-9]``). The callback
  host ``<nonce>.<zone>`` is assembled by :func:`build_oob_payload` alone; the
  zone is collaborator-minted and never observed content.

Why this is *structural*, not convention: :func:`build_oob_payload` has **no
parameter** through which target data could ride, and it **rejects** any nonce or
zone that is not shape-valid (``ValueError``). So "encode ``/etc/passwd`` into the
subdomain" or "``${env:AWS_SECRET}.<nonce>``" is not a payload the carrier can be
*asked* to build — the interpolation slot for arbitrary data does not exist. P6
proves the capability *fired*; it never moves target data over the channel.
"""

from __future__ import annotations

import base64
import re
import secrets
from enum import StrEnum

# A minted nonce is base32(secrets)-lowercased ⇒ strictly ``[a-z2-7]`` ⊂ ``[a-z0-9]``:
# DNS-label-safe, no dot, no ``${``, no ``/``, no interpolation syntax. The validator
# below is the load-bearing guard — the ONLY string a template interpolates must
# match it, so target data (which contains dots / slashes / metacharacters, or is
# simply longer/shorter) can never masquerade as a nonce.
_NONCE_RE = re.compile(r"^[a-z0-9]{16,64}$")

# A collaborator zone/authority is a DNS name and optional ``:port`` — label chars,
# dots, hyphens, digits and a single colon only. It is minted by the collaborator at
# provisioning (never observed content), but is validated here too as defence in
# depth: an authority that is not host-shaped is rejected rather than smuggled into
# a payload. No ``@`` (userinfo), no ``/`` (path), no whitespace, no scheme.
_ZONE_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$")

# Number of random bytes behind a nonce. 16 bytes ⇒ 128 bits ⇒ a base32 nonce of 26
# chars: an accidental collision is negligible (the §P6.2.2 unforgeability argument).
_NONCE_BYTES = 16


class OOBTemplateId(StrEnum):
    """The CLINKZ-OWNED payload template a methodology may SELECT (never author).

    Each id names a fixed capability-class payload shape whose only variable is the
    nonce. The methodology chooses which shape fits the confirmed capability; the
    concrete bytes are produced solely by :func:`build_oob_payload`.

    * ``BLIND_SSRF_URL`` — a bare ``http://`` callback URL for an ``EGRESS_FETCH``
      fetcher (blind SSRF). The first and only class exercised by this build.
    * ``JNDI_LDAP`` — a ``${jndi:ldap://…}`` lookup for a log-sink egress
      (Log4Shell). The canonical shape; used when the collaborator is reachable via
      a delegated wildcard zone (SUBDOMAIN) so the target's LDAP resolution of
      ``<nonce>.<zone>`` calls back.
    * ``JNDI_DNS`` — a ``${jndi:dns://…}`` lookup for a log-sink egress (Log4Shell).
      The JNDI DNS provider queries the nonce as a domain **directly** at the
      collaborator's DNS-leg authority (``host:dns_port``), so it confirms without
      wildcard-DNS delegation or port-53 — the reliable docker-mode channel wired to
      ``_test_log4shell`` (design §P6.5.4: the DNS leg confirms Log4Shell).
    * ``DNS_LOOKUP`` — a bare callback host for a DNS-only egress (blind CMDi
      ``nslookup``). Present for genericity, not wired this build.
    """

    BLIND_SSRF_URL = "blind_ssrf_url"
    JNDI_LDAP = "jndi_ldap"
    JNDI_DNS = "jndi_dns"
    DNS_LOOKUP = "dns_lookup"


class CallbackShape(StrEnum):
    """Where the nonce rides in the callback host — a property of the collaborator.

    * ``SUBDOMAIN`` — the nonce is the leftmost DNS label: ``<nonce>.<zone>``. The
      design's canonical shape (§P6.1.4); requires the collaborator to answer
      wildcard ``*.<zone>`` DNS so the host resolves.
    * ``PATH`` — the host is the fixed collaborator authority and the nonce rides
      in the URL path: ``http://<zone>/<nonce>``. Used when the authority is a
      fixed reachable host/IP (the docker-mode default — guaranteed reachable, no
      wildcard-DNS dependency; §P6.1.1 explicitly allows the HTTP path as the
      nonce carrier).

    Both shapes are exfil-proof by the same construction: the host is built from
    the validated ``zone`` and the validated nonce only.
    """

    SUBDOMAIN = "subdomain"
    PATH = "path"


def mint_nonce(n_bytes: int = _NONCE_BYTES) -> str:
    """Mint a fresh, single-use, opaque, metacharacter-free nonce.

    Cryptographically random (:func:`secrets.token_bytes`), base32-encoded and
    lowercased so the result is strictly ``[a-z2-7]`` ⊂ ``[a-z0-9]``: DNS-label
    safe, carrying no secret and no target data (§P6.1.4). The value exists only
    after this call, so a callback bearing it can only have been produced by
    something that received the one outbound probe carrying it (unforgeability).

    Args:
        n_bytes: Random bytes behind the nonce (default 16 ⇒ 128 bits).

    Returns:
        A lowercase base32 nonce with padding stripped (matches :data:`_NONCE_RE`).
    """
    raw = secrets.token_bytes(max(n_bytes, _NONCE_BYTES))
    return base64.b32encode(raw).decode("ascii").rstrip("=").lower()


def is_valid_nonce(value: str) -> bool:
    """Whether *value* is a shape-valid nonce (``[a-z0-9]{16,64}``)."""
    return bool(_NONCE_RE.fullmatch(value or ""))


def build_oob_payload(
    template_id: OOBTemplateId,
    nonce: str,
    zone: str,
    *,
    shape: CallbackShape,
) -> str:
    """Assemble a concrete OOB payload from a selected template and a minted nonce.

    This is the **carrier** — the single chokepoint where a nonce becomes a
    payload. It is *structurally* incapable of exfiltration (§P6.7.4):

    * It has **no parameter** that accepts target / LLM / source data. The only
      inputs are an :class:`OOBTemplateId` (selects a fixed branch), a ``nonce``,
      and a collaborator ``zone``.
    * Both string inputs are shape-validated and **rejected** on mismatch, so a
      "nonce" like ``${env:X}`` / ``../etc/passwd`` / ``evil.com`` (anything with a
      dot, slash, ``$`` or ``/``) raises :class:`ValueError` — it can never be
      interpolated into the callback host.

    Args:
        template_id: The CLINKZ-OWNED template the methodology selected.
        nonce: A :func:`mint_nonce` value (validated ``[a-z0-9]{16,64}``).
        zone: The collaborator's callback authority (validated host / ``host:port``).
        shape: Where the nonce rides in the host (:class:`CallbackShape`).

    Returns:
        The concrete payload string to inject (e.g. ``http://<nonce>.<zone>/``).

    Raises:
        ValueError: If ``nonce`` or ``zone`` is not shape-valid (the guardrail),
            or ``template_id`` is unknown.
    """
    if not _NONCE_RE.fullmatch(nonce or ""):
        raise ValueError(
            "OOB nonce is not shape-valid [a-z0-9]{16,64} — refusing to build a "
            "payload from non-nonce data (exfil guardrail, §P6.7.4)"
        )
    if not _ZONE_RE.fullmatch(zone or ""):
        raise ValueError(
            "OOB zone is not a valid host authority — refusing to build a payload "
            "(exfil guardrail, §P6.7.4)"
        )

    host = f"{nonce}.{zone}" if shape is CallbackShape.SUBDOMAIN else zone
    path_nonce = "" if shape is CallbackShape.SUBDOMAIN else f"/{nonce}"

    if template_id is OOBTemplateId.BLIND_SSRF_URL:
        return f"http://{host}{path_nonce or '/'}"
    if template_id is OOBTemplateId.JNDI_LDAP:
        # JNDI carries the nonce in the host (and path for the PATH shape) — the
        # lookup egress is the confirmation; Clinkz never serves a gadget (§P6.5.4).
        return f"${{jndi:ldap://{host}{path_nonce}/x}}"
    if template_id is OOBTemplateId.JNDI_DNS:
        # A dns:// JNDI lookup: the DNS provider queries the nonce-bearing name at the
        # collaborator's DNS-leg authority directly (PATH: ``dns://<zone>/<nonce>``),
        # so the nonce reaches the DNS leg with no wildcard delegation. The lookup
        # egress is the confirmation; Clinkz serves no gadget (guardrail 2).
        return f"${{jndi:dns://{host}{path_nonce}}}"
    if template_id is OOBTemplateId.DNS_LOOKUP:
        # A bare host for a DNS-only egress (e.g. ``nslookup <host>``). The PATH
        # shape has no path leg for DNS, so the nonce must ride the subdomain — a
        # fixed-authority collaborator cannot host a DNS-only probe.
        if shape is CallbackShape.PATH:
            raise ValueError(
                "DNS_LOOKUP template requires the SUBDOMAIN shape (no path leg for "
                "a bare DNS callback)"
            )
        return host
    raise ValueError(f"unknown OOB template id: {template_id!r}")
