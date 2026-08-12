"""Weak cryptography, demonstrated — never "the algorithm looks weak".

This is the class where a phantom is easiest to write and hardest to notice,
because almost everything about a token's *appearance* is suggestive and none of
it is proof. "Base64-looking", "short", "no visible entropy", "MD5-length",
"ECB-shaped" — each is a hypothesis, and a report that says "the session token
appears to use a weak encoding" has claimed nothing testable and helped nobody.

So the defining effect is a DEMONSTRATION, in one of two forms, and each one is
something this engine performed rather than observed:

  * **Recoverable plaintext.** We decoded the token and got back a value the
    application chose — our own username, the email we authenticated with, a
    role word, an identifier we hold. Recovering *random bytes* is not recovering
    plaintext: a base64-wrapped random session id decodes perfectly and reveals
    nothing, and confirming on that would confirm on every well-built session
    cookie in the world. The bar is that the decoded content contains a known
    value, and the known value comes from the engagement's own credentials, not
    from a dictionary.

  * **Forgery accepted.** We rebuilt a token under the same scheme with a
    changed plaintext and the server accepted it — with a control proving the
    server rejects a same-shaped token it did not issue. Without that control,
    "the server accepted my token" is indistinguishable from "the server accepts
    anything", which is a different (and separately reportable) defect.

Everything here is deterministic and offline: this module recovers and rebuilds,
and the acceptance half is the caller's live probe.
"""

from __future__ import annotations

import base64
import binascii
import re
import string
from urllib.parse import unquote

from pydantic import BaseModel

#: Minimum fraction of decoded bytes that must be printable ASCII before a
#: decode counts as "plaintext" at all. A random 16-byte session id
#: base64-decodes cleanly and produces mostly unprintable bytes.
_PRINTABLE_RATIO = 0.85

#: Minimum length of a known value before it may anchor a recovery claim. A
#: two-character username would match inside random text often enough to make
#: the claim meaningless.
_MIN_ANCHOR_LENGTH = 4

_PRINTABLE = set(string.printable)


class RecoveredPlaintext(BaseModel):
    """Plaintext recovered from a token, anchored on a value we know.

    Attributes:
        scheme: How it was recovered (``base64``, ``base64:double``, ``hex``,
            ``rot13``, ``xor:<n>``). Named so a reader can repeat it by hand.
        plaintext: The decoded content, with the anchor left visible. This is
            the target's own data about our own principal, and a demonstration
            that cannot be repeated is not a demonstration.
        anchor: The known value found inside it — what makes this recovery
            rather than decoding.
        anchor_kind: Where the anchor came from (``username``, ``email``).
    """

    scheme: str
    plaintext: str
    anchor: str
    anchor_kind: str = ""


def _printable_ratio(raw: bytes) -> float:
    if not raw:
        return 0.0
    text = raw.decode("latin-1")
    return sum(1 for ch in text if ch in _PRINTABLE) / len(text)


def _try_base64(token: str) -> bytes | None:
    candidate = token.strip().replace("-", "+").replace("_", "/")
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        return base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return None


def _try_hex(token: str) -> bytes | None:
    stripped = token.strip()
    if len(stripped) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", stripped):
        return None
    try:
        return bytes.fromhex(stripped)
    except ValueError:
        return None


def _rot13(token: str) -> bytes:
    import codecs

    return codecs.encode(token, "rot_13").encode("latin-1", errors="replace")


def _xor_single_byte(raw: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in raw)


def _candidate_decodes(token: str) -> list[tuple[str, bytes]]:
    """Every (scheme, decoded) pair worth inspecting for *token*.

    Reversible encodings only. This module never attempts to BREAK cryptography:
    an encoding a client can undo is not a secret, and demonstrating that is the
    whole class. A token that resists all of these is simply not recovered, and
    "we could not recover it" is the honest result.
    """
    raw = unquote(token or "").strip()
    if not raw:
        return []
    out: list[tuple[str, bytes]] = [("plain", raw.encode("latin-1", errors="replace"))]

    decoded = _try_base64(raw)
    if decoded is not None:
        out.append(("base64", decoded))
        inner = _try_base64(decoded.decode("latin-1", errors="replace"))
        if inner is not None:
            out.append(("base64:double", inner))
        for key in range(1, 256):
            out.append((f"base64+xor:{key}", _xor_single_byte(decoded, key)))

    hexed = _try_hex(raw)
    if hexed is not None:
        out.append(("hex", hexed))
        for key in range(1, 256):
            out.append((f"hex+xor:{key}", _xor_single_byte(hexed, key)))

    out.append(("rot13", _rot13(raw)))
    return out


def recover_plaintext(
    token: str,
    *,
    known_values: dict[str, str],
) -> RecoveredPlaintext | None:
    """Recover a token's plaintext, anchored on a value the engagement knows.

    Args:
        token: The token as served (cookie value, opaque parameter).
        known_values: ``{kind: value}`` the engagement actually holds — the
            username it authenticated as, the email it registered with. These
            anchor the claim: a decode that does not surface one of them has
            recovered bytes, not plaintext.

    Returns:
        The recovery, or ``None``. ``None`` is the overwhelmingly common answer
        and it is correct: a properly generated session id decodes to random
        bytes under every scheme here, and reporting that as "weak encoding
        detected" would confirm on every target.
    """
    anchors = [
        (kind, value.strip())
        for kind, value in (known_values or {}).items()
        if value and len(value.strip()) >= _MIN_ANCHOR_LENGTH
    ]
    if not anchors:
        return None

    candidates = [
        (scheme, decoded.decode("latin-1", errors="replace"))
        for scheme, decoded in _candidate_decodes(token)
        if _printable_ratio(decoded) >= _PRINTABLE_RATIO
    ]

    # Two passes, exact case first.
    #
    # A single-byte XOR has a SHADOW KEY: 0x20 is exactly the ASCII case bit, so
    # for every real key there is a second key differing by 0x20 whose output is
    # the same text with the case flipped. Both decode to printable text, both
    # contain the anchor case-insensitively, and — because XOR is symmetric —
    # both re-encode to the original token byte for byte. A round-trip check
    # cannot tell them apart; nothing about the token can.
    #
    # What CAN tell them apart is the anchor itself. It is a value this
    # engagement supplied at login, and an application stores it as it was
    # given. So the decode carrying our identity spelled the way WE spelled it
    # is preferred, and the case-insensitive pass is kept only as a fallback for
    # an application that normalises case on the way in.
    #
    # This is a preference, not a proof: with the fallback used, the scheme
    # named in the evidence may be the shadow. It still recovers the plaintext
    # and still re-encodes to the token, so the demonstration holds — but the
    # exact-case pass is what makes it also the recipe the application used.
    for match_case in (True, False):
        for scheme, text in candidates:
            haystack = text if match_case else text.lower()
            for kind, value in anchors:
                needle = value if match_case else value.lower()
                if needle in haystack:
                    return RecoveredPlaintext(
                        scheme=scheme,
                        plaintext=text,
                        anchor=value,
                        anchor_kind=kind,
                    )
    return None


def reencode(plaintext: str, scheme: str) -> str | None:
    """Rebuild a token from *plaintext* under the scheme it was recovered with.

    The forgery half. Only the schemes :func:`recover_plaintext` can undo are
    supported, which is the point: we forge under a scheme we DEMONSTRATED the
    application uses, never under one we guessed.

    Returns:
        The re-encoded token, or ``None`` for a scheme we cannot rebuild.
    """
    raw = plaintext.encode("latin-1", errors="replace")
    if scheme == "plain":
        return plaintext
    if scheme == "base64":
        return base64.b64encode(raw).decode()
    if scheme == "base64:double":
        return base64.b64encode(base64.b64encode(raw)).decode()
    if scheme == "hex":
        return raw.hex()
    if scheme == "rot13":
        import codecs

        return codecs.encode(plaintext, "rot_13")
    if scheme.startswith("base64+xor:"):
        key = int(scheme.split(":", 1)[1])
        return base64.b64encode(_xor_single_byte(raw, key)).decode()
    if scheme.startswith("hex+xor:"):
        key = int(scheme.split(":", 1)[1])
        return _xor_single_byte(raw, key).hex()
    return None


def forge_plaintext(recovered: RecoveredPlaintext, *, replacement: str) -> str | None:
    """Swap the anchor for *replacement* inside the recovered plaintext.

    The minimal edit: everything else about the token — its structure, its
    separators, any counter or timestamp it carries — is left exactly as the
    application built it, so an accepted forgery is evidence about the ONE thing
    that changed.

    Returns:
        The forged token, or ``None`` when the scheme cannot be rebuilt.
    """
    index = recovered.plaintext.lower().find(recovered.anchor.lower())
    if index < 0:
        return None
    forged_plaintext = (
        recovered.plaintext[:index]
        + replacement
        + recovered.plaintext[index + len(recovered.anchor) :]
    )
    return reencode(forged_plaintext, recovered.scheme)


class ForgeryVerdict(BaseModel):
    """Whether a forged token was accepted, with the control that makes it mean something.

    Attributes:
        accepted: The forged token was honoured AND a same-shaped token the
            server never issued was refused. The only state that may confirm.
        forged_honoured: The server treated the forged token as valid.
        control_refused: A random token of the same shape was refused, proving
            the server distinguishes tokens at all.
        detail: One sentence for the evidence.
    """

    accepted: bool = False
    forged_honoured: bool = False
    control_refused: bool = False
    detail: str = ""


def evaluate_forgery(
    *,
    forged_honoured: bool,
    control_honoured: bool,
    forged_token_scheme: str,
    replacement: str,
) -> ForgeryVerdict:
    """Decide a forgery attempt against its control.

    ``control_honoured`` is the outcome of presenting a random token of the same
    shape. If the server honours THAT too, it is not validating tokens at all —
    a real and serious defect, but a different one, and reporting it as
    "forgeable token" would misdescribe it. So the control failing costs the
    confirmation.
    """
    if not forged_honoured:
        return ForgeryVerdict(
            control_refused=not control_honoured,
            detail="the server refused the forged token — the scheme is authenticated",
        )
    if control_honoured:
        return ForgeryVerdict(
            forged_honoured=True,
            control_refused=False,
            detail=(
                "the server honoured the forged token, but ALSO honoured a random token "
                "of the same shape it never issued — so it is not validating tokens at "
                "all, which is a different defect from a forgeable scheme and is not "
                "evidence that the scheme was broken"
            ),
        )
    return ForgeryVerdict(
        accepted=True,
        forged_honoured=True,
        control_refused=True,
        detail=(
            f"a token rebuilt under the application's own {forged_token_scheme} scheme "
            f"carrying {replacement!r} was honoured as that principal, while a random "
            f"token of the same shape was refused — so the scheme encodes identity "
            f"without authenticating it"
        ),
    )


__all__ = [
    "ForgeryVerdict",
    "RecoveredPlaintext",
    "evaluate_forgery",
    "forge_plaintext",
    "recover_plaintext",
    "reencode",
]
