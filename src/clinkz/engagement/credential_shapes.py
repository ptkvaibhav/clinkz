"""The one credential-shape vocabulary — what a secret LOOKS like.

Redaction used to know only what a secret *is*: the operator's password, the
value we were handed at intake, registered in :mod:`clinkz.engagement.secrets`
and substring-replaced at every artifact writer. That is correct and it is not
enough. A live engagement captures credential material the operator never
supplied and we therefore never registered — the session token the target
issued us. A run against OWASP Juice Shop wrote five live JWTs into
``trace.jsonl``; one decoded to a payload carrying the account's password hash
and TOTP secret. The writers were covered. The *shape* was not.

So this module is the second half of the definition. It states, in one place,
what credential material looks like:

  * **JWT** — ``eyJ<header>.<payload>.<signature>``, gated on the header
    actually decoding to JSON, so arbitrary base64 is not swept up.
  * **Authorization-style values** — ``Bearer …``, ``Basic …``, ``Token …``,
    whether inline in a header line, in a curl argv, or standing alone as the
    value of a header dict.
  * **Cookie values** — names kept, values removed. A cookie NAME is
    load-bearing evidence in this codebase (``Endpoint.sets_cookies`` records
    names precisely because a value is authentication material); a cookie VALUE
    is the session.
  * **Vendor API keys** and **private-key blocks** — the shapes a scanner has
    always looked for.

**One vocabulary, two consumers, deliberately asymmetric.**
:mod:`clinkz.engagement.secrets` consumes it on the WRITE path via
:func:`redact_shapes`; :mod:`clinkz.engagement.artifact_scan` consumes it on the
AUDIT path via :func:`find_shapes`. Sharing the definition is what stops the
two from drifting — a checker that carries its own private notion of "secret"
can only ever confirm the writer's blind spots, which is precisely how five
JWTs sat in an artifact under a check that reported zero leaks.

The asymmetry is as deliberate as the sharing. The scanner additionally applies
an entropy heuristic; the redactor never does. This is a penetration-testing
tool, and its evidence is *made of* strings that look alarming — payloads,
hashes we are proving we extracted, base64 in an XXE response. An entropy rule
on the write path would shred the findings; on the audit path a false positive
costs a human ten seconds. Redaction is structural and conservative. Scanning
is broad and merely reports.

**Fingerprints, not values.** A redacted token is replaced by a fingerprint —
a salted hash prefix plus non-secret identifying claims — so an artifact can
still say *this* token was accepted where *that* one was rejected without
carrying anything replayable. The salt is per-process: correlation within a
bundle is what evidence needs, and a per-process salt additionally means a
short, low-entropy value (a preference cookie) cannot be recovered from its
fingerprint by hashing a dictionary.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets as _stdlib_secrets
from dataclasses import dataclass
from typing import Final

#: Marker every shape replacement starts with. Also the idempotence guard: a
#: value already carrying this is left alone, so re-writing an artifact (which
#: ``TraceWriter.attach_parsed_output`` does) cannot redact a redaction.
REDACTION_MARKER: Final = "[REDACTED:"

#: Per-process fingerprint salt. Rotated by :func:`reset_fingerprint_salt` in
#: tests. Never written to an artifact.
_SALT: bytes = _stdlib_secrets.token_bytes(16)

#: Hex characters of the fingerprint hash. 48 bits — enough that two distinct
#: tokens in one bundle are distinguishable, far too few to invert.
_FP_HEX: Final = 12


def reset_fingerprint_salt() -> None:
    """Draw a fresh fingerprint salt.

    Called between tests so one test's fingerprints cannot be asserted against
    another's. Production code never calls it: a single salt per process is
    what makes fingerprints comparable within one engagement's bundle.
    """
    global _SALT
    _SALT = _stdlib_secrets.token_bytes(16)


def fingerprint(value: str) -> str:
    """Return the salted hash prefix identifying *value* without revealing it."""
    digest = hashlib.sha256(_SALT + value.encode("utf-8", "replace")).hexdigest()
    return digest[:_FP_HEX]


# ---------------------------------------------------------------------------
# Shapes
# ---------------------------------------------------------------------------

#: A JWT-shaped string. The header segment must start ``eyJ`` (base64url of
#: ``{"``); the third segment may be empty (``alg=none``) or absent-but-dotted.
#: Matching is a candidate test only — :func:`_decode_jwt_header` decides.
JWT_RE: Final = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*)?")

#: Authorization schemes whose value is credential material.
_AUTH_SCHEMES: Final = ("bearer", "basic", "token", "apikey", "digest", "negotiate", "jwt")

#: ``Authorization: Bearer xyz`` appearing inline in text — a raw header block,
#: a joined curl argv, an LLM prompt echoing a request.
AUTH_INLINE_RE: Final = re.compile(
    r"(?i)\b((?:proxy-)?authorization\s*:\s*)"
    r"((?:" + "|".join(_AUTH_SCHEMES) + r")\s+)?"
    r"([^\s,;\"']+)"
)

#: A standalone header VALUE that is itself credential material — what a
#: ``{"Authorization": "Bearer …"}`` dict yields once the walker has separated
#: key from value. Anchored, so prose mentioning a bearer token is untouched.
AUTH_VALUE_RE: Final = re.compile(
    r"(?i)^((?:" + "|".join(_AUTH_SCHEMES) + r")\s+)([^\s]{8,})$",
)

#: ``Cookie:`` / ``Set-Cookie:`` inline in text. Values go, names stay.
COOKIE_INLINE_RE: Final = re.compile(r"(?i)\b((?:set-)?cookie\s*:\s*)([^\r\n]+)")

#: curl's cookie and userinfo flags in a joined argv.
CURL_COOKIE_RE: Final = re.compile(r"(?<!\S)(-b|--cookie)\s+(\S+)")
CURL_USERPWD_RE: Final = re.compile(r"(?<!\S)(-u|--user)\s+(\S+)")

#: A single ``name=value`` pair inside a cookie string.
_COOKIE_PAIR_RE: Final = re.compile(r"([^=;,\s]+)=([^;,\r\n]*)")

#: Vendor key shapes. Kept in step with ``.claude/hooks/secret_guard.py`` — that
#: guard protects the repository, this vocabulary protects the deliverable, and
#: a shape known to one should be known to both.
API_KEY_RES: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("anthropic", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai", re.compile(r"sk-(?!ant-)[A-Za-z0-9_-]{32,}")),
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("google", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("slack", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("gitlab", re.compile(r"glpat-[A-Za-z0-9_-]{20,}")),
)

#: A PEM private-key block. The whole block, not just the banner: half a key in
#: an artifact is still a leaked key.
PRIVATE_KEY_RE: Final = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
    re.DOTALL,
)

#: Dict keys whose VALUE is credential material regardless of what it looks
#: like. Consulted by the key-aware structure walker in
#: :mod:`clinkz.engagement.secrets` — a ``Set-Cookie`` value has no intrinsic
#: shape, so the only thing that identifies it is the key it arrived under.
CREDENTIAL_HEADER_KEYS: Final = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "apikey",
        "x-auth-token",
        "x-authorization",
        "x-access-token",
        "x-session-token",
        "x-csrf-token",
        "x-xsrf-token",
        "authentication",
        "www-authenticate",
        "bearer_token",
        "bearertoken",
        "access_token",
        "id_token",
        "refresh_token",
        "session_token",
        "token",
        "password",
        "passwd",
        "secret",
    }
)

#: Cheap substring triggers. Running a dozen regexes over every string a trace
#: writer touches would tax the hot path for nothing; these decide in one ``in``
#: test whether any rule can possibly match. Each is specific enough to be rare
#: in ordinary text — a bare ``"gh"`` would fire on every "through" and "right"
#: and defeat the point of having a fast path at all.
_TRIGGERS: Final = (
    "eyj",
    "authorization",
    "cookie",
    "-----begin",
    "bearer ",
    "basic ",
    "token ",
    "apikey ",
    "digest ",
    "negotiate ",
    "jwt ",
    "sk-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "akia",
    "aiza",
    "xox",
    "glpat-",
    " -u ",
    " --user ",
    " -b ",
)


@dataclass(frozen=True)
class ShapeHit:
    """One credential shape located in a piece of text.

    Attributes:
        kind: Shape identifier — ``jwt``, ``authorization``, ``cookie``,
            ``api_key``, ``private_key``.
        detail: Non-secret description (scheme, cookie name, vendor).
        fingerprint: Salted hash prefix of the matched value.
        start: Character offset of the match.
        length: Length of the matched value.
    """

    kind: str
    detail: str
    fingerprint: str
    start: int
    length: int


# ---------------------------------------------------------------------------
# JWT decoding
# ---------------------------------------------------------------------------


def _b64_segment(segment: str) -> bytes | None:
    """Decode one base64url segment, tolerating truncation.

    A trace summary truncates mid-token, so the tail segment is routinely
    invalid. Decoding the longest valid prefix is what lets a truncated token
    still be recognised — and a truncated JWT is still a leaked JWT, because the
    header and most of the payload survive.

    At most four lengths are tried, never a walk back down the string. Base64
    decodes on four-character groups, so dropping 0–3 characters covers every
    alignment; a descending loop would instead do O(n) decodes of an O(n) string
    on every candidate, and the candidate here is a value the TARGET chose.
    """
    for drop in range(4):
        end = len(segment) - drop
        if end < 4:
            break
        chunk = segment[:end]
        try:
            return base64.urlsafe_b64decode(chunk + "=" * (-len(chunk) % 4))
        except (binascii.Error, ValueError):
            continue
    return None


def _decode_jwt_header(token: str) -> dict[str, object] | None:
    """Return the decoded JOSE header, or ``None`` when this is not a JWT.

    The header is what distinguishes a token from any other dotted base64: it
    must decode to a JSON object naming an algorithm or type. Requiring the
    PAYLOAD to decode would miss exactly the tokens most likely to be in an
    artifact — the truncated ones.
    """
    head = token.split(".", 1)[0]
    raw = _b64_segment(head)
    if raw is None:
        return None
    try:
        parsed = json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    if "alg" not in parsed and "typ" not in parsed:
        return None
    return parsed


def _decode_jwt_payload(token: str) -> dict[str, object] | None:
    """Return the decoded claim set, or ``None`` when it does not decode."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    raw = _b64_segment(parts[1])
    if raw is None:
        return None
    try:
        parsed = json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _claim(payload: dict[str, object] | None, name: str) -> str:
    """Read one registered claim as a short string, or ``""``."""
    if not payload:
        return ""
    value = payload.get(name)
    if value is None or isinstance(value, (dict, list)):
        return ""
    text = str(value)
    return text[:64]


def fingerprint_jwt(token: str) -> str:
    """Render a JWT as a correlatable, non-replayable fingerprint.

    Carries the salted hash prefix, the algorithm, the registered ``iss``/``sub``
    claims when present, and the NAMES of the remaining claims — never a claim
    value. Naming the claims matters: it is how a reader of the artifact learns
    that the token's payload carried ``password`` and ``totpSecret`` without the
    artifact carrying them.

    Args:
        token: The raw token.

    Returns:
        A ``[REDACTED:JWT …]`` string.
    """
    header = _decode_jwt_header(token) or {}
    payload = _decode_jwt_payload(token)
    parts = [f"{REDACTION_MARKER}JWT sha256={fingerprint(token)}"]
    alg = header.get("alg")
    if alg:
        parts.append(f"alg={alg}")
    for registered in ("iss", "sub"):
        value = _claim(payload, registered)
        if value:
            parts.append(f"{registered}={value}")
    if payload is not None:
        names = sorted(str(k) for k in payload)
        # Nested claim containers are where an application hides identity
        # material; naming their keys too is what made the Juice Shop payload
        # legible ("data carries password") without reproducing it.
        for key in list(names):
            nested = payload.get(key)
            if isinstance(nested, dict):
                inner = ",".join(sorted(str(k) for k in nested))
                names[names.index(key)] = f"{key}{{{inner}}}"
        parts.append("claims=[" + ",".join(names) + "]")
    else:
        parts.append("claims=<undecodable>")
    return " ".join(parts) + "]"


# ---------------------------------------------------------------------------
# The write path — redaction
# ---------------------------------------------------------------------------


def _already_redacted(value: str) -> bool:
    """Whether *value* already carries a redaction of either kind.

    Matches the shape marker ``[REDACTED:`` and the value-registry's plain
    ``[REDACTED]`` alike, so the two layers cannot redact each other's output.
    """
    return "[REDACTED" in value


def _redact_cookie_string(cookie_string: str) -> str:
    """Redact the VALUES in a cookie string, keeping every name."""
    if _already_redacted(cookie_string):
        return cookie_string

    def repl(match: re.Match[str]) -> str:
        name, value = match.group(1), match.group(2)
        if not value:
            return match.group(0)
        return f"{name}={REDACTION_MARKER}COOKIE sha256={fingerprint(value)}]"

    return _COOKIE_PAIR_RE.sub(repl, cookie_string)


def redact_shapes(text: str) -> str:
    """Replace every credential SHAPE in *text* with a fingerprint.

    Order is load-bearing: JWTs are replaced first so a ``Bearer eyJ…`` header
    yields the richer JWT fingerprint (which names the claims) rather than the
    generic authorization one.

    Args:
        text: Arbitrary text about to be written to a durable artifact.

    Returns:
        *text* with credential shapes replaced. Idempotent — text already
        carrying replacements is returned unchanged by every rule.
    """
    if not text:
        return text
    lowered = text.lower()
    if not any(trigger in lowered for trigger in _TRIGGERS):
        return text

    out = text

    if "eyj" in lowered:

        def jwt_repl(match: re.Match[str]) -> str:
            token = match.group(0)
            if _decode_jwt_header(token) is None:
                return token
            return fingerprint_jwt(token)

        out = JWT_RE.sub(jwt_repl, out)

    if "-----begin" in lowered:
        out = PRIVATE_KEY_RE.sub(f"{REDACTION_MARKER}PRIVATE_KEY]", out)

    if "authorization" in lowered:

        def auth_inline_repl(match: re.Match[str]) -> str:
            label, scheme, value = match.group(1), match.group(2) or "", match.group(3)
            if _already_redacted(value):
                return match.group(0)
            kind = (scheme.strip() or "opaque").lower()
            return f"{label}{scheme}{REDACTION_MARKER}AUTH {kind} sha256={fingerprint(value)}]"

        out = AUTH_INLINE_RE.sub(auth_inline_repl, out)

    # A bare "Bearer <token>" with no header label around it — what a header dict
    # yields once the walker has separated key from value, and what a list of
    # header values holds. Anchored, so prose mentioning a bearer token is safe.
    standalone = AUTH_VALUE_RE.match(out)
    if standalone is not None and not _already_redacted(out):
        scheme, value = standalone.group(1), standalone.group(2)
        kind = scheme.strip().lower()
        out = f"{scheme}{REDACTION_MARKER}AUTH {kind} sha256={fingerprint(value)}]"

    if "cookie" in lowered or " -b " in f" {out} ":

        def cookie_inline_repl(match: re.Match[str]) -> str:
            return match.group(1) + _redact_cookie_string(match.group(2))

        out = COOKIE_INLINE_RE.sub(cookie_inline_repl, out)
        out = CURL_COOKIE_RE.sub(lambda m: f"{m.group(1)} {_redact_cookie_string(m.group(2))}", out)

    if "-u " in out or "--user " in out:

        def userpwd_repl(match: re.Match[str]) -> str:
            value = match.group(2)
            if _already_redacted(value) or ":" not in value:
                return match.group(0)
            user, _, password = value.partition(":")
            masked = f"{REDACTION_MARKER}AUTH basic sha256={fingerprint(password)}]"
            return f"{match.group(1)} {user}:{masked}"

        out = CURL_USERPWD_RE.sub(userpwd_repl, out)

    for vendor, pattern in API_KEY_RES:
        if pattern.search(out):

            def api_key_repl(match: re.Match[str], v: str = vendor) -> str:
                return f"{REDACTION_MARKER}API_KEY {v} sha256={fingerprint(match.group(0))}]"

            out = pattern.sub(api_key_repl, out)

    return out


def redact_header_value(key: str, value: str) -> str:
    """Redact a header value identified by its KEY rather than its shape.

    A ``Set-Cookie`` value has no intrinsic shape — it is whatever the target
    chose — so the only thing that identifies it as credential material is the
    key it arrived under. The structure walker calls this whenever a dict key is
    in :data:`CREDENTIAL_HEADER_KEYS`.

    Cookie-ish keys keep their cookie NAMES (a name is evidence, a value is the
    session); everything else is replaced whole.

    Args:
        key: The dict key the value arrived under.
        value: The value.

    Returns:
        The redacted value.
    """
    if not value or _already_redacted(value):
        return value
    normalised = key.strip().lower()
    if normalised in ("cookie", "set-cookie"):
        return _redact_cookie_string(value)
    # A JWT-valued header keeps the richer fingerprint.
    shaped = redact_shapes(value)
    if shaped != value:
        return shaped
    return f"{REDACTION_MARKER}HEADER {normalised} sha256={fingerprint(value)}]"


# ---------------------------------------------------------------------------
# The audit path — detection
# ---------------------------------------------------------------------------


def find_shapes(text: str) -> list[ShapeHit]:
    """Locate every credential shape in *text* without modifying it.

    The audit-path counterpart of :func:`redact_shapes`, sharing its
    definitions so a shape the redactor removes is a shape the scanner looks
    for. Values already carrying a redaction marker are not reported — a
    fingerprint is the fix, not the defect.

    Args:
        text: Artifact content.

    Returns:
        Every hit, in document order.
    """
    if not text:
        return []
    hits: list[ShapeHit] = []
    lowered = text.lower()

    if "eyj" in lowered:
        for match in JWT_RE.finditer(text):
            token = match.group(0)
            header = _decode_jwt_header(token)
            if header is None:
                continue
            payload = _decode_jwt_payload(token)
            claims = ",".join(sorted(str(k) for k in payload)) if payload else "<undecodable>"
            hits.append(
                ShapeHit(
                    kind="jwt",
                    detail=f"alg={header.get('alg', '?')} claims=[{claims}]",
                    fingerprint=fingerprint(token),
                    start=match.start(),
                    length=len(token),
                )
            )

    if "-----begin" in lowered:
        for match in PRIVATE_KEY_RE.finditer(text):
            hits.append(
                ShapeHit(
                    kind="private_key",
                    detail="PEM private key block",
                    fingerprint=fingerprint(match.group(0)),
                    start=match.start(),
                    length=len(match.group(0)),
                )
            )

    if "authorization" in lowered:
        for match in AUTH_INLINE_RE.finditer(text):
            value = match.group(3)
            if _already_redacted(value):
                continue
            scheme = (match.group(2) or "opaque").strip().lower()
            hits.append(
                ShapeHit(
                    kind="authorization",
                    detail=f"scheme={scheme}",
                    fingerprint=fingerprint(value),
                    start=match.start(3),
                    length=len(value),
                )
            )

    standalone = AUTH_VALUE_RE.match(text)
    if standalone is not None and not _already_redacted(text):
        hits.append(
            ShapeHit(
                kind="authorization",
                detail=f"scheme={standalone.group(1).strip().lower()}",
                fingerprint=fingerprint(standalone.group(2)),
                start=standalone.start(2),
                length=len(standalone.group(2)),
            )
        )

    if "cookie" in lowered:
        for match in COOKIE_INLINE_RE.finditer(text):
            block = match.group(2)
            if _already_redacted(block):
                continue
            for pair in _COOKIE_PAIR_RE.finditer(block):
                name, value = pair.group(1), pair.group(2)
                if not value or _already_redacted(value):
                    continue
                hits.append(
                    ShapeHit(
                        kind="cookie",
                        detail=f"name={name}",
                        fingerprint=fingerprint(value),
                        start=match.start(2) + pair.start(2),
                        length=len(value),
                    )
                )

    for vendor, pattern in API_KEY_RES:
        for match in pattern.finditer(text):
            hits.append(
                ShapeHit(
                    kind="api_key",
                    detail=f"vendor={vendor}",
                    fingerprint=fingerprint(match.group(0)),
                    start=match.start(),
                    length=len(match.group(0)),
                )
            )

    hits.sort(key=lambda hit: hit.start)
    return hits


def jwt_payload_claim_names(token: str) -> list[str]:
    """Claim NAMES in *token*'s payload — used by tests and the scanner report.

    Returns an empty list when the token is not a decodable JWT.
    """
    payload = _decode_jwt_payload(token)
    if payload is None:
        return []
    names = sorted(str(k) for k in payload)
    for key in list(payload):
        nested = payload.get(key)
        if isinstance(nested, dict):
            names.extend(f"{key}.{inner}" for inner in sorted(str(k) for k in nested))
    return sorted(names)


__all__ = [
    "API_KEY_RES",
    "AUTH_INLINE_RE",
    "AUTH_VALUE_RE",
    "COOKIE_INLINE_RE",
    "CREDENTIAL_HEADER_KEYS",
    "JWT_RE",
    "PRIVATE_KEY_RE",
    "REDACTION_MARKER",
    "ShapeHit",
    "find_shapes",
    "fingerprint",
    "fingerprint_jwt",
    "jwt_payload_claim_names",
    "redact_header_value",
    "redact_shapes",
    "reset_fingerprint_salt",
]
