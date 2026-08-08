"""What a client-side DOM source looks like — one vocabulary, two readers.

The DOM-XSS methodology has always known these patterns; it uses them to decide
whether a page is even a candidate. The **planner** did not, and that was a
measured ranking defect rather than a theoretical one.

On a live DVWA engagement (`a2cbcc4d`) the DOM-XSS class ranked entirely on path
words it shared with `_test_javascript_attacks` — ``javascript``, ``js``,
``client``. So a general "javascript" page and a ``.js`` asset graded ABOVE the
application's actual DOM-XSS route, whose path says none of those; the plan cap
then dropped the one endpoint where the class could have fired, the class
dispatched twenty times, and every single dispatch reported
``source_sink_pairs=0``. The engine's own RANKING FAILURE check saw it — 92
inversions — and the class still never reached its surface.

A path word was the wrong signal to begin with. Whether a DOM sink is reachable
is not a property of what a route is *called*; it is a property of what the page
actually returned. This module makes that an **observed response feature**, the
same shape as ``Endpoint.sets_cookies`` and ``Endpoint.has_form``: the crawl
records that a page's own JavaScript reads a DOM source, and the planner ranks
on the observation instead of on a guess.

Kept in its own module so the scan agent can import it without importing the
exploit agent, and so there is exactly one definition of "a DOM source" rather
than a copy per reader.
"""

from __future__ import annotations

import re

#: Client-side sources of attacker-controlled data — where the *attacker's*
#: bytes enter the page's JavaScript.
DOM_SOURCE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"document\.location(?:\.hash|\.search|\.href|\.pathname)?", re.IGNORECASE),
    re.compile(r"window\.location(?:\.hash|\.search|\.href|\.pathname)?", re.IGNORECASE),
    re.compile(r"\blocation\.(?:hash|search|href|pathname)\b", re.IGNORECASE),
    re.compile(r"document\.URL\b", re.IGNORECASE),
    re.compile(r"document\.documentURI\b", re.IGNORECASE),
    re.compile(r"document\.referrer\b", re.IGNORECASE),
    re.compile(r"window\.name\b", re.IGNORECASE),
    re.compile(r"unescape\s*\(\s*document\.(?:URL|location)", re.IGNORECASE),
    re.compile(
        r"decodeURI(?:Component)?\s*\(\s*(?:document\.(?:URL|location)|location)",
        re.IGNORECASE,
    ),
]


#: Sinks where attacker-controlled data is parsed or executed.
DOM_SINK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"document\.write(?:ln)?\s*\(", re.IGNORECASE),
    re.compile(r"\.innerHTML\s*=", re.IGNORECASE),
    re.compile(r"\.outerHTML\s*=", re.IGNORECASE),
    re.compile(r"\.insertAdjacentHTML\s*\(", re.IGNORECASE),
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"\bnew\s+Function\s*\(", re.IGNORECASE),
    re.compile(r"\bsetTimeout\s*\(\s*[\"']", re.IGNORECASE),
    re.compile(r"\bsetInterval\s*\(\s*[\"']", re.IGNORECASE),
    re.compile(r"\.setAttribute\s*\(\s*[\"']on", re.IGNORECASE),
    re.compile(r"location\s*(?:\.href)?\s*=", re.IGNORECASE),
]


#: A URL parameter NAME that a DOM sink's own guard keys on.
#:
#: Matches the shapes a script uses to ask "is my parameter present in the URL"
#: before it does anything with it — ``indexOf("q=")``, ``includes('q=')``,
#: ``search.match(/q=/)``. The name is read out of the TARGET's own JavaScript
#: at runtime; nothing here encodes any application's vocabulary.
_SINK_GUARD_TOKEN = re.compile(
    r"""(?:indexOf|includes|search|match)\s*\(?\s*['"/]([A-Za-z_][A-Za-z0-9_.\[\]-]{0,63})=""",
    re.IGNORECASE,
)


def sink_guard_url_tokens(script: str) -> list[str]:
    """Parameter names a script requires in the URL before its sink will run.

    A DOM sink is very often behind a guard: the page checks that *its* parameter
    is in the URL and only then reads and writes it. A probe that does not carry
    that parameter never enters the branch, so the sink is unreachable and the
    oracle correctly reports that nothing executed — about a page that is
    genuinely vulnerable.

    That is not hypothetical. In engagement `f9ddc9b1` the crawl recorded only
    the bare route, the P7 probe navigated to it with the payload in the
    fragment, and DVWA's

        if (document.location.href.indexOf("default=") >= 0) { … document.write(…) }

    never fired. The engine had already extracted that exact line into the
    lead's own evidence — it knew the token and did not use it.

    Args:
        script: The script excerpt the source→sink analysis recorded.

    Returns:
        Deduplicated parameter names, in first-seen order.
    """
    names: list[str] = []
    for match in _SINK_GUARD_TOKEN.finditer(script or ""):
        name = match.group(1)
        if name and name not in names:
            names.append(name)
    return names


def body_reads_dom_source(body: str) -> bool:
    """Whether the page's own JavaScript carries a DOM source AND a sink.

    **Both halves are required, and that is the whole design of this predicate.**

    The obvious version — "does the body mention a DOM source" — was built,
    shipped to a live engagement, and did real damage. Applications serve a
    shared script on every page, and any script that reads ``location`` to
    highlight the current nav item satisfies a source-only test. So the
    precondition came back TRUE for essentially the entire application, the
    DOM-XSS class graded every endpoint as its own surface, and the global plan
    cap then filled with DOM-XSS tasks: SQL injection was pushed off
    ``/vulnerabilities/sqli/?id=`` onto the login form, and a run that had
    reported 21 findings reported 10 — losing SQLi, command injection, file
    inclusion, upload, brute force, CSRF, stored XSS and weak-session, none of
    which have anything to do with this class.

    That is precisely the failure the ``body_param`` note in
    ``_CLASS_PRECONDITIONS`` warns about: a precondition broad enough to match
    most of an application does not rank that class's surface, it starves every
    other class. A precondition earns its place by being SELECTIVE.

    Requiring a sink as well restores that. A source flowing to
    ``document.write``/``innerHTML``/``eval`` is the shape that makes a DOM-XSS
    test able to fire at all, and it is rare — which is exactly what a ranking
    signal needs to be. This is intentionally the cheap, whole-body version of
    the per-script-block analysis the methodology's own phase 1 performs: the
    planner only needs to know the page is worth visiting, and a page that has
    both in unrelated blocks costs one dispatch that reports no candidate.

    Args:
        body: A response body, as served.

    Returns:
        ``True`` when the body matches both a source and a sink pattern.
    """
    if not body:
        return False
    if not any(pattern.search(body) for pattern in DOM_SOURCE_PATTERNS):
        return False
    return any(pattern.search(body) for pattern in DOM_SINK_PATTERNS)


__all__ = [
    "DOM_SINK_PATTERNS",
    "DOM_SOURCE_PATTERNS",
    "body_reads_dom_source",
    "sink_guard_url_tokens",
]
