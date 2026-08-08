"""Generic, default-deny classifier for destructive requests.

The predecessor of this module was
:func:`clinkz.agents._url_safety.is_destructive_form_submission`, whose rules
were shaped by the two incidents that produced it: a crawl that GET-toggled
DVWA's WAF, and a per-parameter fuzz that submitted DVWA's password-change form
~25 times and left ``admin``'s hash as ``md5("")``. Those rules were correct but
bound to the shape of the thing that bit us — an HTML form, on a benchmark.

Against a production application the binding has to be looser and the coverage
wider. This module classifies a REQUEST — ``(method, url, field names, label
text)`` — not a form, so it sits at the HTTP chokepoint and sees traffic that
never passed through a form parser: a JSON API call, a REST verb, a link the
planner synthesized.

**Default-deny.** A skipped probe costs a line in the "what was not tested"
section. A deleted production record costs the engagement. So:

  * a token match refuses, even when the surrounding context is ambiguous;
  * ``DELETE`` refuses unconditionally — the verb is the harm;
  * ``PUT``/``PATCH`` at a path naming a sensitive resource refuses, because a
    whole-resource replace is a destroy-and-recreate whatever the field names
    say;
  * every rule that :func:`clinkz.agents._url_safety.is_destructive_form_submission`
    already applied is preserved **verbatim** (:func:`_legacy_form_verdict`), so
    this module can only ever refuse MORE than its predecessor, never less.

``POST`` alone is deliberately NOT a refusal. POST is how an application says
"submit this form", and refusing it wholesale would reduce the engine to a
read-only crawler — every injection class it exists to prove needs to submit
something. POST is decided by the verb and noun signals below.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict

# ---------------------------------------------------------------------------
# Categories
# ---------------------------------------------------------------------------

#: The DEFINING categories from the engagement contract. Kept as constants so a
#: refusal in the action log and a line in the report's "not tested" section
#: name the same thing.
CATEGORY_DELETION = "deletion"
CATEGORY_CREDENTIAL_CHANGE = "credential_change"
CATEGORY_IDENTITY_CHANGE = "identity_change"
CATEGORY_PAYMENT = "payment"
CATEGORY_CANCELLATION = "cancellation"
CATEGORY_KEY_REVOCATION = "key_revocation"
CATEGORY_BULK_MESSAGING = "bulk_messaging"
CATEGORY_DATA_RESET = "data_reset"
CATEGORY_SESSION_DESTRUCTION = "session_destruction"
CATEGORY_SECURITY_CONTROL = "security_control_toggle"
CATEGORY_UNSAFE_METHOD = "unsafe_method"

# ---------------------------------------------------------------------------
# Token vocabularies
#
# Matched against TOKENS, not substrings: the haystack is split on separators
# and camelCase humps first, so ``deleteAccount`` and ``/api/users/5/delete``
# both yield ``delete`` while ``undeleted_rows`` does not accidentally match a
# bare ``delete``. Substring matching is retained only inside
# :func:`_legacy_form_verdict`, which must stay bit-compatible with its
# predecessor.
# ---------------------------------------------------------------------------

_DELETION_TOKENS = frozenset(
    {
        "delete",
        "del",
        "remove",
        "destroy",
        "purge",
        "erase",
        "wipe",
        "drop",
        "trash",
        "discard",
        "unlink",
        "unpublish",
    }
)

_PAYMENT_TOKENS = frozenset(
    {
        "pay",
        "payment",
        "payments",
        "checkout",
        "charge",
        "billing",
        "invoice",
        "refund",
        "transfer",
        "withdraw",
        "withdrawal",
        "deposit",
        "purchase",
        "buy",
        "paypal",
        "stripe",
        "iban",
        "creditcard",
        "cardnumber",
        "cvv",
        "cvc",
    }
)

# Cancellation splits into tokens that mean it on their own and tokens that only
# mean it next to a resource. ``disable`` and ``close`` are common enough as UI
# chrome ("Close" on a modal) that refusing them bare would cost real surface;
# ``disable`` + ``account`` is unambiguous.
_CANCELLATION_TOKENS = frozenset(
    {"cancel", "cancellation", "unsubscribe", "terminate", "deactivate", "suspend"}
)

_WEAK_CANCELLATION_TOKENS = frozenset({"disable", "close"})

# Verbs that destroy a container's CONTENTS rather than the container. Weak on
# their own (``?empty=true`` is an ordinary filter flag) but unambiguous next to
# a resource: "empty cart", "clear orders".
_WEAK_EMPTYING_TOKENS = frozenset({"empty", "clear", "flush"})

_REVOCATION_TOKENS = frozenset({"revoke", "rotate", "regenerate", "reissue", "invalidate"})

_KEY_NOUNS = frozenset(
    {"key", "keys", "apikey", "token", "tokens", "secret", "secrets", "certificate", "cert"}
)

# ``message`` and ``publish`` are absent on purpose: they are nouns far more
# often than verbs, and a guestbook's ``mtxMessage`` field is precisely the
# stored-XSS surface the engine exists to prove.
_MESSAGING_VERBS = frozenset({"send", "broadcast", "notify", "invite", "mail", "email", "sms"})

# Breadth must mean "many real recipients". ``users``/``members`` are absent:
# they name REST collections (``/api/Users``) at least as often as audiences,
# and pairing one with a bare ``email`` field would refuse ordinary registration.
_MESSAGING_BREADTH = frozenset({"all", "bulk", "mass", "everyone", "batch", "subscribers"})

_MESSAGING_STANDALONE = frozenset({"newsletter", "campaign", "broadcast", "mailshot", "blast"})

_RESET_VERBS = frozenset(
    {"reset", "reinstall", "reinitialize", "reinit", "truncate", "restore", "factory", "rollback"}
)

_RESET_NOUNS = frozenset(
    {"db", "database", "data", "setup", "install", "system", "config", "configuration", "schema"}
)

_SESSION_DESTRUCTION_TOKENS = frozenset({"logout", "signout", "logoff", "deauth", "deauthorize"})

# Security posture controls. The bare word ``security`` is deliberately absent:
# it appears as an ordinary content parameter (``view_source.php?id=fi&security=low``)
# and blocking it would remove legitimate surface. A toggle is recognised by a
# control noun co-occurring with an on/off verb, or by the specific query keys
# the predecessor guard already knew.
_SECURITY_CONTROL_NOUNS = frozenset(
    {"waf", "firewall", "ids", "ips", "phpids", "protection", "seclev", "securitylevel"}
)

_SECURITY_CONTROL_VERBS = frozenset({"on", "off", "enable", "disable", "toggle", "set", "submit"})

#: Query keys whose mere presence flips a security control. Preserved verbatim
#: from the predecessor guard.
_STATE_CHANGING_QUERY_KEYS = frozenset({"phpids", "seclev_submit", "seclev"})

# Resource nouns that make a whole-resource replace (PUT/PATCH) or removal
# unacceptable. POST to these is fine — that is creation.
_SENSITIVE_RESOURCE_NOUNS = frozenset(
    {
        "user",
        "users",
        "account",
        "accounts",
        "profile",
        "profiles",
        "member",
        "members",
        "credential",
        "credentials",
        "password",
        "passwords",
        "email",
        "role",
        "roles",
        "permission",
        "permissions",
        "key",
        "keys",
        "token",
        "tokens",
        "card",
        "cards",
        "payment",
        "payments",
        "subscription",
        "subscriptions",
        "order",
        "orders",
        "invoice",
        "invoices",
        "basket",
        "cart",
        "file",
        "files",
        "backup",
        "backups",
    }
)

#: Methods that mutate. GET/HEAD/OPTIONS are read verbs and are not gated here
#: (a GET that mutates is caught by :func:`is_state_changing_request` instead).
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: Methods for which a sensitive-resource path alone is enough to refuse.
_WHOLE_RESOURCE_METHODS = frozenset({"PUT", "PATCH", "DELETE"})

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SEPARATORS = re.compile(r"[^A-Za-z0-9]+")

# A parameter VALUE is only read for semantics when the APPLICATION plausibly
# wrote it — ``?action=delete``, ``?Submit=Delete Record`` — never when WE did.
#
# This distinction is load-bearing, not cosmetic. Our own probes carry the exact
# vocabulary this module refuses on: ``?id=1' OR 1=1; DROP TABLE--`` contains
# ``drop``, a command-injection probe contains ``rm``, an LFI probe contains
# ``passwd``. Tokenizing values indiscriminately would make the safety rail
# refuse the engine's own payloads and silently reduce an authorized engagement
# to a crawler.
#
# The discriminator is the CHARACTER SET, not the shape. Every injection payload
# this engine sends carries at least one of these — a quote, a bracket, a
# separator, an escape — while a human-readable action label carries none.
#
# An earlier version tested the whole value against ``^[A-Za-z0-9_.\-]{1,24}$``,
# which meant a single space defeated it: ``?action=delete`` was refused but
# ``?action=Delete%20this%20record`` sailed through, and a crawler would then
# follow that link and re-send it on every subsequent probe. Bounding LENGTH
# per token rather than per value closes that without weakening the payload
# exclusion at all.
_PAYLOAD_CHARS = frozenset("'\"<>;%/\\()*=`{}[]|&$\n\r\t")

#: Longest single word that can still be an application's action verb. Applied
#: per TOKEN after splitting, never to the whole value.
_MAX_VALUE_TOKEN_LEN = 24

#: Values longer than this are not read for semantics at all. A genuine action
#: label is short; anything this long is data, and splitting it would only add
#: noise to the token set.
_MAX_VALUE_LEN = 256


def _application_authored(value: str) -> bool:
    """Whether *value* looks like text the APPLICATION wrote, not a payload we did.

    Args:
        value: A raw parameter or field value.

    Returns:
        ``True`` when the value is safe to read for destructive semantics.
    """
    if not value or len(value) > _MAX_VALUE_LEN:
        return False
    return not any(char in _PAYLOAD_CHARS for char in value)


class DestructiveVerdict(BaseModel):
    """Why a request was (or was not) refused.

    Attributes:
        refused: ``True`` when the request must not be sent.
        category: One of the ``CATEGORY_*`` constants; ``""`` when allowed.
        reason: One sentence an operator can read in the action log.
        signal: The exact token or method that decided it — so a refusal can be
            argued with, and a false refusal diagnosed, from the log alone.
    """

    model_config = ConfigDict(frozen=True)

    refused: bool = False
    category: str = ""
    reason: str = ""
    signal: str = ""


_ALLOWED = DestructiveVerdict()


# ---------------------------------------------------------------------------
# Tokenization
# ---------------------------------------------------------------------------


def _tokens(*parts: str, max_token_len: int | None = None) -> set[str]:
    """Split *parts* into lowercase word tokens.

    Separators and camelCase humps both split, so ``deleteAllUsers``,
    ``delete_all_users`` and ``/admin/delete/all`` yield the same token set.

    Args:
        *parts: Arbitrary text fragments (path, field names, labels, ...).
        max_token_len: Drop tokens longer than this. Applied to values, whose
            length is a weak signal that we are looking at data rather than a
            label; never applied to paths or field names, which the application
            always authored.

    Returns:
        The set of lowercase tokens.
    """
    out: set[str] = set()
    for part in parts:
        if not part:
            continue
        spaced = _CAMEL_BOUNDARY.sub(" ", str(part))
        for token in _SEPARATORS.split(spaced):
            if not token:
                continue
            if max_token_len is not None and len(token) > max_token_len:
                continue
            out.add(token.lower())
    return out


def _request_tokens(
    url: str,
    field_names: list[str] | None,
    labels: list[str] | None,
    values: list[str] | None = None,
) -> tuple[set[str], set[str]]:
    """Return ``(all_tokens, query_keys)`` for a request.

    Three tiers of trust, and the distinction is what keeps the classifier from
    refusing the engine's own probes:

    * **Path, query keys, field names, labels** — the application authored all of
      these. A submit button's caption is the page's own words and may contain
      anything ("Create / Reset Database"), so it is tokenized unconditionally.
    * **Query values and field values** — WE author these during a fuzz, so they
      pass :func:`_application_authored` first and are bounded per token.

    Query KEYS are returned separately because the security-control rule keys on
    exact query-key names.
    """
    try:
        parts = urlsplit(url or "")
    except ValueError:
        parts = urlsplit("")

    query_pairs = parse_qsl(parts.query, keep_blank_values=True) if parts.query else []
    query_keys = {k.lower() for k, _ in query_pairs}

    tokens = _tokens(
        parts.path,
        *(k for k, _ in query_pairs),
        *(field_names or []),
        *(labels or []),
    )
    tokens |= _tokens(
        *(v for _, v in query_pairs if _application_authored(v)),
        *(v for v in (values or []) if _application_authored(v)),
        max_token_len=_MAX_VALUE_TOKEN_LEN,
    )
    return tokens, query_keys


# ---------------------------------------------------------------------------
# The classifier
# ---------------------------------------------------------------------------


def classify_request(
    method: str,
    url: str,
    *,
    field_names: list[str] | None = None,
    labels: list[str] | None = None,
    field_types: list[str] | None = None,
    values: list[str] | None = None,
) -> DestructiveVerdict:
    """Classify a request as destructive (refuse) or not.

    Args:
        method: HTTP method.
        url: Absolute or relative request URL.
        field_names: Names of the fields the request would submit.
        labels: Button / link / label text associated with the action. Submit
            button values belong here — ``value="Delete account"`` is often the
            only place the semantics are written down. The application authored
            these, so they are read verbatim.
        values: Non-label field values the PAGE shipped with (a hidden field's
            default, say). Filtered through :func:`_application_authored` first,
            because a synthesized pseudo-form can carry a value we authored.
        field_types: Input types parallel to *field_names*; a ``password`` type
            is an authentication-material signal even when the field is named
            something opaque.

    Returns:
        A :class:`DestructiveVerdict`.
    """
    verb = (method or "GET").upper()
    tokens, query_keys = _request_tokens(url, field_names, labels, values)
    types = {t.lower() for t in (field_types or [])}

    # 1. The verb is the harm.
    if verb == "DELETE":
        return DestructiveVerdict(
            refused=True,
            category=CATEGORY_UNSAFE_METHOD,
            reason="HTTP DELETE removes a resource outright.",
            signal="method=DELETE",
        )

    # 2. Session destruction and security-posture toggles apply to every method:
    #    both poison the shared engagement session rather than damaging the
    #    client, and both are refused for the whole engagement's sake.
    session_hit = tokens & _SESSION_DESTRUCTION_TOKENS
    if session_hit:
        return DestructiveVerdict(
            refused=True,
            category=CATEGORY_SESSION_DESTRUCTION,
            reason="Would destroy the shared engagement session.",
            signal=sorted(session_hit)[0],
        )

    security_verdict = _security_control_verdict(tokens, query_keys)
    if security_verdict.refused:
        return security_verdict

    # 3. Destructive semantics. Checked for every method, not just mutating
    #    ones: plenty of applications delete on GET (``?action=delete&id=5``),
    #    which is precisely the case a crawler walks into.
    for verdict_fn in (
        _deletion_verdict,
        _payment_verdict,
        _revocation_verdict,
        _reset_verdict,
        _bulk_messaging_verdict,
        _cancellation_verdict,
    ):
        verdict = verdict_fn(tokens)
        if verdict.refused:
            return verdict

    # 4. Credential / identity mutation — the rules inherited verbatim from the
    #    form guard, applied here to the request's own field names.
    cred_verdict = _credential_identity_verdict(tokens, types)
    if cred_verdict.refused:
        return cred_verdict

    # 5. Uncertainty rule: a whole-resource replace or removal against a
    #    sensitive resource. We cannot know what the body would overwrite, so we
    #    refuse rather than find out on a live application.
    if verb in _WHOLE_RESOURCE_METHODS:
        noun_hit = tokens & _SENSITIVE_RESOURCE_NOUNS
        if noun_hit:
            return DestructiveVerdict(
                refused=True,
                category=CATEGORY_UNSAFE_METHOD,
                reason=(
                    f"HTTP {verb} against a sensitive resource replaces or removes it "
                    "wholesale; the effect on live data is not knowable in advance."
                ),
                signal=f"method={verb} resource={sorted(noun_hit)[0]}",
            )

    return _ALLOWED


def _deletion_verdict(tokens: set[str]) -> DestructiveVerdict:
    hit = tokens & _DELETION_TOKENS
    if hit:
        return DestructiveVerdict(
            refused=True,
            category=CATEGORY_DELETION,
            reason="Request semantics indicate deletion of a resource.",
            signal=sorted(hit)[0],
        )
    weak_hit = tokens & _WEAK_EMPTYING_TOKENS
    noun_hit = tokens & _SENSITIVE_RESOURCE_NOUNS
    if weak_hit and noun_hit:
        return DestructiveVerdict(
            refused=True,
            category=CATEGORY_DELETION,
            reason="Request would empty or clear a resource's contents.",
            signal=f"{sorted(weak_hit)[0]}+{sorted(noun_hit)[0]}",
        )
    return _ALLOWED


def _payment_verdict(tokens: set[str]) -> DestructiveVerdict:
    hit = tokens & _PAYMENT_TOKENS
    if not hit:
        return _ALLOWED
    return DestructiveVerdict(
        refused=True,
        category=CATEGORY_PAYMENT,
        reason="Request semantics indicate a payment or funds movement.",
        signal=sorted(hit)[0],
    )


def _revocation_verdict(tokens: set[str]) -> DestructiveVerdict:
    verb_hit = tokens & _REVOCATION_TOKENS
    if not verb_hit:
        return _ALLOWED
    noun_hit = tokens & _KEY_NOUNS
    if not noun_hit:
        return _ALLOWED
    return DestructiveVerdict(
        refused=True,
        category=CATEGORY_KEY_REVOCATION,
        reason="Request would revoke or rotate a key, token, or certificate.",
        signal=f"{sorted(verb_hit)[0]}+{sorted(noun_hit)[0]}",
    )


def _reset_verdict(tokens: set[str]) -> DestructiveVerdict:
    verb_hit = tokens & _RESET_VERBS
    if not verb_hit:
        return _ALLOWED
    noun_hit = tokens & _RESET_NOUNS
    if not noun_hit:
        return _ALLOWED
    return DestructiveVerdict(
        refused=True,
        category=CATEGORY_DATA_RESET,
        reason="Request would reset or reinitialise application data.",
        signal=f"{sorted(verb_hit)[0]}+{sorted(noun_hit)[0]}",
    )


def _bulk_messaging_verdict(tokens: set[str]) -> DestructiveVerdict:
    standalone = tokens & _MESSAGING_STANDALONE
    if standalone:
        return DestructiveVerdict(
            refused=True,
            category=CATEGORY_BULK_MESSAGING,
            reason="Request would send a bulk message to real recipients.",
            signal=sorted(standalone)[0],
        )
    verb_hit = tokens & _MESSAGING_VERBS
    breadth_hit = tokens & _MESSAGING_BREADTH
    if verb_hit and breadth_hit:
        return DestructiveVerdict(
            refused=True,
            category=CATEGORY_BULK_MESSAGING,
            reason="Request would send a message to a broad recipient set.",
            signal=f"{sorted(verb_hit)[0]}+{sorted(breadth_hit)[0]}",
        )
    return _ALLOWED


def _cancellation_verdict(tokens: set[str]) -> DestructiveVerdict:
    hit = tokens & _CANCELLATION_TOKENS
    if hit:
        return DestructiveVerdict(
            refused=True,
            category=CATEGORY_CANCELLATION,
            reason="Request semantics indicate a cancellation or deactivation.",
            signal=sorted(hit)[0],
        )
    weak_hit = tokens & _WEAK_CANCELLATION_TOKENS
    noun_hit = tokens & _SENSITIVE_RESOURCE_NOUNS
    if weak_hit and noun_hit:
        return DestructiveVerdict(
            refused=True,
            category=CATEGORY_CANCELLATION,
            reason="Request would disable or close a sensitive resource.",
            signal=f"{sorted(weak_hit)[0]}+{sorted(noun_hit)[0]}",
        )
    return _ALLOWED


def _credential_identity_verdict(tokens: set[str], types: set[str]) -> DestructiveVerdict:
    """Password/email change rules, applied to a request's own tokens.

    Same discriminator as the form guard: a *mutation qualifier* is what
    separates changing an existing credential from submitting one (login) or
    creating a new one (registration). Both of those must keep working — the
    brute-force class depends on login, and registration destroys nothing.
    """
    if not (tokens & _LEGACY_MUTATION_QUALIFIERS):
        return _ALLOWED
    auth_hit = tokens & _LEGACY_AUTH_TOKENS
    if auth_hit or "password" in types:
        return DestructiveVerdict(
            refused=True,
            category=CATEGORY_CREDENTIAL_CHANGE,
            reason="Request would overwrite authentication material.",
            signal=sorted(auth_hit)[0] if auth_hit else "input[type=password]",
        )
    identity_hit = tokens & _LEGACY_IDENTITY_TOKENS
    if identity_hit:
        return DestructiveVerdict(
            refused=True,
            category=CATEGORY_IDENTITY_CHANGE,
            reason="Request would mutate the identity an account is recovered by.",
            signal=sorted(identity_hit)[0],
        )
    return _ALLOWED


def _security_control_verdict(tokens: set[str], query_keys: set[str]) -> DestructiveVerdict:
    """Refuse anything that flips the target's own security posture."""
    key_hit = query_keys & _STATE_CHANGING_QUERY_KEYS
    if key_hit:
        return DestructiveVerdict(
            refused=True,
            category=CATEGORY_SECURITY_CONTROL,
            reason="Request would change the target's security level or WAF state.",
            signal=f"query:{sorted(key_hit)[0]}",
        )
    noun_hit = tokens & _SECURITY_CONTROL_NOUNS
    if noun_hit and (tokens & _SECURITY_CONTROL_VERBS):
        return DestructiveVerdict(
            refused=True,
            category=CATEGORY_SECURITY_CONTROL,
            reason="Request would toggle a protective control on the target.",
            signal=sorted(noun_hit)[0],
        )
    return _ALLOWED


# ---------------------------------------------------------------------------
# Legacy form vocabulary — preserved verbatim
#
# These are the exact token tuples the predecessor guard used, kept as-is so
# :func:`_legacy_form_verdict` reproduces its decisions byte-for-byte. New
# vocabulary goes in the frozensets above, never here.
# ---------------------------------------------------------------------------

_LEGACY_AUTH_MATERIAL = ("password", "passwd", "pwd", "passphrase")
_LEGACY_IDENTITY = ("email", "e-mail", "username", "user_name", "userid", "user_id")
_LEGACY_MUTATION = (
    "new",
    "change",
    "update",
    "reset",
    "current",
    "old",
    "confirm",
    "edit",
    "modify",
    "credential",
    "account",
    "profile",
    "settings",
)
_LEGACY_DESTRUCTIVE_ACTIONS = (
    "delete",
    "remove",
    "destroy",
    "purge",
    "deactivate",
    "transfer",
    "withdraw",
    "revoke",
)

# Token-set forms of the legacy vocabularies, for the token-based rules above.
_LEGACY_AUTH_TOKENS = frozenset(_LEGACY_AUTH_MATERIAL)
_LEGACY_IDENTITY_TOKENS = frozenset({"email", "username", "userid", "user", "mail"})
_LEGACY_MUTATION_QUALIFIERS = frozenset(_LEGACY_MUTATION)


def _legacy_form_verdict(form: dict[str, Any], action_url: str = "") -> DestructiveVerdict:
    """The predecessor guard's decision, reproduced exactly.

    Substring matching over a joined haystack — deliberately NOT the token
    matching used elsewhere in this module, because reproducing the old
    behaviour exactly is the point. Any request this refuses must keep being
    refused; the token rules only add to it.
    """
    fields = form.get("fields") or []
    field_names = [str(fld.get("name") or "").lower() for fld in fields]
    field_types = [str(fld.get("type") or "").lower() for fld in fields]
    path = ""
    if action_url:
        try:
            path = (urlsplit(action_url).path or "").lower()
        except ValueError:
            path = ""
    haystack = " ".join([str(form.get("action") or "").lower(), path, *field_names])

    if str(form.get("method") or "").upper() == "DELETE":
        return DestructiveVerdict(
            refused=True,
            category=CATEGORY_UNSAFE_METHOD,
            reason="Form declares the DELETE method.",
            signal="method=DELETE",
        )
    for tok in _LEGACY_DESTRUCTIVE_ACTIONS:
        if tok in haystack:
            return DestructiveVerdict(
                refused=True,
                category=CATEGORY_DELETION,
                reason="Form action names a destructive verb.",
                signal=tok,
            )

    if not any(q in haystack for q in _LEGACY_MUTATION):
        return _ALLOWED

    has_auth_material = any(t == "password" for t in field_types) or any(
        tok in haystack for tok in _LEGACY_AUTH_MATERIAL
    )
    if has_auth_material:
        return DestructiveVerdict(
            refused=True,
            category=CATEGORY_CREDENTIAL_CHANGE,
            reason="Form would overwrite authentication material.",
            signal="password",
        )
    for tok in _LEGACY_IDENTITY:
        if tok in haystack:
            return DestructiveVerdict(
                refused=True,
                category=CATEGORY_IDENTITY_CHANGE,
                reason="Form would mutate account identity.",
                signal=tok,
            )
    return _ALLOWED


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def classify_form_submission(form: dict[str, Any], action_url: str = "") -> DestructiveVerdict:
    """Classify a parsed form submission.

    Runs the preserved predecessor rules FIRST (so nothing it refused can slip
    through), then the general request classifier over the same form — which
    additionally sees submit-button labels, query parameters, and every category
    the predecessor never had.

    Args:
        form: ``{action, method, fields:[{name,type,value}]}`` — the parsed HTML
            form or the synthesized JSON pseudo-form of the same shape.
        action_url: The form's resolved absolute action URL, when known.

    Returns:
        A :class:`DestructiveVerdict`.
    """
    legacy = _legacy_form_verdict(form, action_url)
    if legacy.refused:
        return legacy

    fields = form.get("fields") or []
    names = [str(fld.get("name") or "") for fld in fields]
    types = [str(fld.get("type") or "") for fld in fields]
    # A submit/button value IS the human-readable label ("Delete my account") —
    # often the only place a form's semantics are written down — and the page
    # wrote it, so it is read verbatim even when it contains punctuation
    # ("Create / Reset Database").
    labels = [
        str(fld.get("value") or "")
        for fld in fields
        if str(fld.get("type") or "").lower() in ("submit", "button")
    ]
    labels.extend(str(fld.get("label") or "") for fld in fields if fld.get("label"))

    # Other field values carry the action too — ``<input type="hidden" name="op"
    # value="delete">`` renders nothing at all — but a synthesized pseudo-form
    # can carry a value WE authored, so these go through the payload filter.
    values = [
        str(fld.get("value") or "")
        for fld in fields
        if str(fld.get("type") or "").lower() not in ("submit", "button")
    ]

    target = action_url or str(form.get("action") or "")
    method = str(form.get("method") or "POST").upper()
    return classify_request(
        method, target, field_names=names, labels=labels, field_types=types, values=values
    )


def is_state_changing_request(url: str, method: str = "GET") -> bool:
    """Whether merely issuing this request would mutate the target.

    The navigation guard: used by the crawler and the exploit planner to decide
    whether a discovered link may be followed at all. Backed by the same
    classifier, so a ``/admin/users/5/delete`` link is refused on a production
    application exactly as a WAF toggle is on a benchmark.

    Args:
        url: Absolute or relative URL.
        method: The method that would be used; defaults to ``GET``.

    Returns:
        ``True`` when the URL must not be visited.
    """
    if not url:
        return False
    return classify_request(method, url).refused


def subresource_guard_spec() -> dict[str, list[str]]:
    """The destructive vocabulary, serialized for the P7 browser's request rail.

    A rendered page issues requests this process never chose: an ``<img
    src="/logout">``, a ``fetch('/admin/reset')``, a beacon. Those are the same
    hazard :func:`classify_request` exists for, but the decision has to be made
    *inside* the browser's routing callback — which, in docker tool-mode, is a
    bare ``python3`` in the tools container with nothing of Clinkz importable.
    So the vocabulary travels there as data rather than as a second copy of the
    classifier: this module stays the one place the words live.

    The projection is deliberately **coarser and stricter** than
    :func:`classify_request`. That function weighs verb/noun co-occurrence
    because it judges a request an operator's methodology intended to send;
    this list is matched as bare tokens against a request the *page* chose, and
    over-refusing there costs a subresource load while under-refusing costs the
    engagement's session. Only vocabularies that are unambiguous **on their
    own** are included — the weak sets (``disable``, ``close``, ``empty``,
    ``clear``), the bare resource nouns (``user``, ``profile``) and the common
    English verbs (``mail``, ``send``) are all left out, because a token match
    on those would refuse ordinary page assets.

    A refusal is never silent: the runner records every blocked request on the
    verdict, so a stylesheet that happened to tokenize onto ``drop`` is visible
    to a reviewer rather than quietly missing.

    Returns:
        ``blocked_path_tokens`` and ``blocked_query_keys``, both sorted so the
        job a run sends is byte-stable across processes.
    """
    tokens: set[str] = set()
    for vocabulary in (
        _SESSION_DESTRUCTION_TOKENS,
        _DELETION_TOKENS,
        _CANCELLATION_TOKENS,
        _PAYMENT_TOKENS,
        _RESET_VERBS,
        _REVOCATION_TOKENS,
        _SECURITY_CONTROL_NOUNS,
        _MESSAGING_STANDALONE,
    ):
        tokens |= vocabulary
    return {
        "blocked_path_tokens": sorted(tokens),
        "blocked_query_keys": sorted(_STATE_CHANGING_QUERY_KEYS),
    }


__all__ = [
    "CATEGORY_BULK_MESSAGING",
    "CATEGORY_CANCELLATION",
    "CATEGORY_CREDENTIAL_CHANGE",
    "CATEGORY_DATA_RESET",
    "CATEGORY_DELETION",
    "CATEGORY_IDENTITY_CHANGE",
    "CATEGORY_KEY_REVOCATION",
    "CATEGORY_PAYMENT",
    "CATEGORY_SECURITY_CONTROL",
    "CATEGORY_SESSION_DESTRUCTION",
    "CATEGORY_UNSAFE_METHOD",
    "MUTATING_METHODS",
    "DestructiveVerdict",
    "classify_form_submission",
    "classify_request",
    "is_state_changing_request",
    "subresource_guard_spec",
]
