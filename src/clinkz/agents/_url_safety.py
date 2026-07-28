"""Probe safety: never mutate the target's security posture while mapping it.

Two guards live here, one per carrier:

  * :func:`is_state_changing_url` — **navigation.** A link that flips server-side
    state when merely visited.
  * :func:`is_destructive_form_submission` — **form submission.** A form whose
    submission would overwrite authentication material, mutate account identity,
    or destroy/transfer a resource.

A black-box pentest crawler must *map* the application without *changing* it.
Some links flip server-side state when merely visited (most are GET-triggered):

  - ``security.php?phpids=on`` / ``?phpids=off`` — toggles DVWA's PHPIDS WAF.
  - ``security.php?seclev_submit=...`` — changes the difficulty level.
  - ``logout.php`` / ``signout`` — destroys the authenticated session.

Because every v2 phase shares one engagement session (recon → scan → exploit),
following any of these during recon/scan silently poisons that session for the
later phases. The concrete failure that motivated this module: the Scan Agent's
endpoint-enrichment step GET-visited ``security.php?phpids=on``, which enabled
PHPIDS for the rest of the engagement — so every Exploit-phase injection payload
(SQLi quote, reflected-XSS tag, CMDi separator) came back as the generic
``Hacking attempt detected and logged.`` block page and verification confirmed
nothing, even though the same methodologies pass in isolation against a clean
session.

The fix is to never *visit* and never *emit* such links: the crawler skips them
and the Exploit planner drops them, so the shared session's security posture is
left exactly as the operator set it.

The submission guard exists for the same reason one rung down. Per-parameter
fuzzing submits a form once per field per probe; against a credential-mutating
form that is a live password change repeated tens of times. Engagement
``e183af87`` submitted DVWA's password-change form ~25 times and left ``admin``'s
hash as ``md5("")`` — the engagement destroyed the target's credentials and
blocked every later phase. Mapping an application must never overwrite its
accounts, so such forms are refused at the submit chokepoint rather than fuzzed.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse, urlsplit

# Query-parameter keys whose presence flips a server-side security/session
# control. Matched case-insensitively against the URL's query keys. Kept tight
# on purpose: broad keys like ``security`` would wrongly exclude legitimate
# content endpoints such as ``view_source.php?id=fi&security=low``.
_STATE_CHANGING_QUERY_KEYS = frozenset(
    {
        "phpids",  # DVWA WAF toggle (GET-triggered): security.php?phpids=on/off
        "seclev_submit",  # DVWA security-level form submit
        "seclev",
    }
)

# Path fragments that change application/session state on their own. ``logout``
# / ``signout`` drop the session; both are universal, not DVWA-specific.
_STATE_CHANGING_PATH_FRAGMENTS = (
    "logout",
    "signout",
    "logoff",
)


def is_state_changing_url(url: str) -> bool:
    """Return ``True`` if visiting ``url`` would mutate the target's state.

    Used by the Scan Agent (crawl/enrichment) and the Exploit planner to avoid
    following links that toggle a WAF, change the security level, or log out —
    actions that poison the shared engagement session. Conservative: anything
    that does not match a known state-changing signature is treated as safe so
    coverage is never silently reduced.

    Args:
        url: Absolute or relative URL string discovered by a crawler.

    Returns:
        ``True`` when the URL matches a state-changing signature (a known WAF /
        security-level toggle query key, or a logout-style path), else
        ``False``.
    """
    if not url:
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        # Unparseable URL — treat as safe; the HTTP layer will reject it.
        return False

    path = parts.path.lower()
    for fragment in _STATE_CHANGING_PATH_FRAGMENTS:
        if fragment in path:
            return True

    if parts.query:
        keys = {k.lower() for k in parse_qs(parts.query, keep_blank_values=True)}
        if keys & _STATE_CHANGING_QUERY_KEYS:
            return True

    return False


# ---------------------------------------------------------------------------
# Form-submission safety (destructive-mutation guard)
# ---------------------------------------------------------------------------

# Field-name / path tokens naming AUTHENTICATION MATERIAL. Deliberately excludes
# ``token``: an anti-CSRF ``user_token`` rides along on almost every form and
# would block the whole form surface.
_AUTH_MATERIAL_TOKENS = ("password", "passwd", "pwd", "passphrase")

# Tokens naming ACCOUNT IDENTITY — the value an account is recovered/logged in by.
_IDENTITY_TOKENS = ("email", "e-mail", "username", "user_name", "userid", "user_id")

# What separates a *mutation* of existing auth material from a plain login (submit
# an existing credential) or a fresh registration (create a new one). A login form
# carries none of these, so brute-force testing is unaffected; a change/reset form
# carries at least one in a field name (``password_new``, ``password_current``) or
# in the resolved path (``/rest/user/change-password``, ``/account/settings``).
#
# This is the discriminator, NOT "two password fields": a registration form also
# has ``password`` + ``passwordRepeat``, and creating an account destroys nothing.
_MUTATION_QUALIFIERS = (
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

# Verbs whose submission destroys or moves a resource outright. These need no
# credential signal — the action is the harm.
_DESTRUCTIVE_ACTION_TOKENS = (
    "delete",
    "remove",
    "destroy",
    "purge",
    "deactivate",
    "transfer",
    "withdraw",
    "revoke",
)


def is_destructive_form_submission(form: dict[str, Any], action_url: str = "") -> bool:
    """Return ``True`` if submitting *form* would destroy or overwrite target state.

    The form-submission counterpart to :func:`is_state_changing_url`: a
    methodology may *read* such a form (parse it, count its tokens, reason about
    its shape) but must never *submit* it, because a submission overwrites
    authentication material, mutates account identity, or destroys/transfers a
    resource. Per-parameter fuzzing submits a form once per field per probe, so
    an unguarded credential form is silently changed tens of times per run.

    True when any of:

      1. The declared method is ``DELETE`` (the verb is the harm).
      2. A destructive verb (:data:`_DESTRUCTIVE_ACTION_TOKENS`) appears in a
         field name or the resolved path.
      3. An authentication-material signal (:data:`_AUTH_MATERIAL_TOKENS`, or a
         ``type="password"`` input) co-occurs with a mutation qualifier
         (:data:`_MUTATION_QUALIFIERS`) — a password *change/reset*, not a login.
      4. An account-identity signal (:data:`_IDENTITY_TOKENS`) co-occurs with a
         mutation qualifier — an email/username change hijacks the account.

    Deliberately NOT destructive: a plain **login** form (credentials submitted,
    nothing mutated — brute-force testing depends on this) and a plain
    **registration** form (creates an account, destroys nothing). Both lack a
    mutation qualifier, which is exactly what rules 3 and 4 key on.

    Conservative by construction: it refuses a submission on a *name* signal, so
    a form that merely reads as credential-mutating is skipped rather than
    fuzzed. That trades some coverage for never damaging the target — the right
    direction for an autonomous engagement.

    Args:
        form: A parsed ``{action, method, fields:[{name,type,value}]}`` dict (or
            the synthesized JSON pseudo-form of the same shape).
        action_url: The form's resolved absolute action URL, when the caller has
            it. Consulted for the path signal so a JSON pseudo-form — whose
            ``action`` is empty and whose sensitivity lives in the path — is
            still classified correctly.

    Returns:
        ``True`` when the submission would mutate credentials/identity or destroy
        a resource, else ``False``.
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
        return True
    if any(tok in haystack for tok in _DESTRUCTIVE_ACTION_TOKENS):
        return True

    has_mutation_qualifier = any(q in haystack for q in _MUTATION_QUALIFIERS)
    if not has_mutation_qualifier:
        return False

    has_auth_material = any(t == "password" for t in field_types) or any(
        tok in haystack for tok in _AUTH_MATERIAL_TOKENS
    )
    if has_auth_material:
        return True
    return any(tok in haystack for tok in _IDENTITY_TOKENS)


# ---------------------------------------------------------------------------
# Session-value setter reference scraping
# ---------------------------------------------------------------------------

# Quoted URL-ish tokens containing "session" — links, form actions, and JS
# string args (``popUp('session-input.php')`` / ``window.open("...")``). The
# basename predicate below narrows these to actual value-setter pages.
_SESSION_SETTER_TOKEN_RE = re.compile(r"""['"]([^'"<>\s]*session[^'"<>\s]*)['"]""", re.IGNORECASE)


def _is_session_setter_basename(last_seg: str) -> bool:
    """Whether a URL's last path segment names a session-value setter page.

    ``session-input.php`` (DVWA's setter) matches directly; a bare ``session``
    token additionally requires a ``set``/``input`` signal so incidental refs
    (``sessionStorage``, a ``sessions.js`` bundle) are not mistaken for a
    setter. Kept deliberately tight — the caller's link gate is the real
    correctness filter, but a loose scrape wastes gate round-trips.
    """
    low = last_seg.lower()
    if "session-input" in low:
        return True
    return "session" in low and ("input" in low or "set" in low)


def find_session_setter_urls(page_url: str, body: str) -> list[str]:
    """Resolve same-origin session-value *setter* URLs referenced by *body*.

    Scrapes quoted URL-ish tokens (including ``onclick``/JS string refs such as
    DVWA's ``popUp('session-input.php')``) whose basename names a session-value
    setter, resolves them against *page_url*, and keeps the same-origin ones.
    A path-shaped token (``.`` or ``/``) is required so a bare identifier is not
    mistaken for a URL. Deduped, order-preserving.

    This is a **pure scrape** — it applies neither scope nor state-change
    guards; callers (the Scan crawler and the Exploit ``_harvest_session_vectors``
    link gate) apply ``scope.contains`` + :func:`is_state_changing_url` before
    acting on a candidate. Returns ``[]`` for empty/parameterless bodies.
    """
    if not body:
        return []
    try:
        origin = urlsplit(page_url)
    except ValueError:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for raw in _SESSION_SETTER_TOKEN_RE.findall(body):
        token = raw.strip()
        if "." not in token and "/" not in token:
            continue
        candidate = urljoin(page_url, token)
        if candidate in seen:
            continue
        seen.add(candidate)
        parsed = urlparse(candidate)
        if (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc):
            continue
        last_seg = parsed.path.rsplit("/", 1)[-1]
        if not _is_session_setter_basename(last_seg):
            continue
        found.append(candidate)
    return found


__all__ = [
    "find_session_setter_urls",
    "is_destructive_form_submission",
    "is_state_changing_url",
]
