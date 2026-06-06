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

from urllib.parse import parse_qs, urlsplit

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


__all__ = ["is_state_changing_url"]
