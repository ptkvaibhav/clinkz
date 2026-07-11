"""Crawl/probe safety: skip links that mutate the target's security posture.

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
"""

from __future__ import annotations

import re
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


__all__ = ["find_session_setter_urls", "is_state_changing_url"]
