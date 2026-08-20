"""URL-shape judgements shared by the crawl and the exploit planner.

Both phases have to answer the same question about a discovered URL — *how
likely is this to be an application surface worth spending budget on?* — and
both used to answer it with their own copy of the vocabulary. That duplication
was not academic: the Scan agent visited "the first 80 crawl URLs" and the
Exploit planner kept "the first 150 candidate tasks", and in both places the
selection inside a tie was made by the crawler's emission order. A concurrent
crawler does not emit in a stable order, so two identical runs against an
unchanged target enriched different pages and planned different tasks.

The functions here are **pure and total**: same URL in, same grade out, on any
run and any machine. That is what lets the callers turn "the first N in crawl
order" into "the best N in a deterministic order", without moving any budget.

Nothing here decides *whether* a URL may be fetched — that is
:mod:`clinkz.agents._url_safety`'s job and it runs first. This module only
decides what order the survivors are worth looking at in.
"""

from __future__ import annotations

from urllib.parse import urlparse

# Static assets are not worth exploit probing beyond header hygiene, and are not
# worth opening during enrichment at all — they carry no form and no link.
STATIC_ASSET_EXTENSIONS: frozenset[str] = frozenset(
    {
        "css",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "svg",
        "ico",
        "woff",
        "woff2",
        "ttf",
        "eot",
        "map",
        "pdf",
        "zip",
        "mp4",
        "webp",
    }
)

# Documentation / translation artifacts a crawl surfaces in bulk (a README and
# its per-locale siblings). Not an executable surface — they carry no sink, so
# probing them only spends budget a real endpoint needed.
DOC_ASSET_EXTENSIONS: frozenset[str] = frozenset({"md", "markdown", "rst", "txt", "log"})

# Crawler-artifact path fragments — endpoints whose path contains one of these
# are deprioritised in planning (source / help viewers and the like). They are
# not real exploit surfaces and crowd canonical vulnerable endpoints out of the
# planning prompt window. Doubled-path artifacts are detected structurally
# instead (:func:`has_repeated_path_block`) rather than by naming one app's
# doubled prefix, which is what this tuple used to do.
# Matched against the path, so each entry must identify the *page*, never merely
# a directory a page happens to sit under. A bare ``/source/`` segment was in
# this tuple and cost real coverage once class-relevance ordering started reading
# it: an app that mounts a live handler under a ``source`` directory
# (``/open_redirect/source/low.php?redirect=``) had that endpoint graded as crawl
# noise and sorted to the back of every class bucket, so ``_test_open_redirect``
# never dispatched against it. A directory name is not evidence about the route;
# the viewer *filenames* below are.
LOW_VALUE_PATH_FRAGMENTS: tuple[str, ...] = (
    "view_source",
    "view_help",
    "instructions.php",
    "phpinfo.php",
    "/readme",
    "/changelog",
    "/license",
)


def has_repeated_path_block(path: str) -> bool:
    """Whether *path* repeats an adjacent block of segments — a crawl artifact.

    ``/vulnerabilities/upload/`` joined against a page already under
    ``/vulnerabilities/`` yields ``/vulnerabilities/vulnerabilities/upload/``:
    a relative-link resolution bug in the crawl, not a route. These 404 and each
    one still consumes a task slot per applicable vuln-class, which is how a
    150-task budget gets spent on nothing.

    Detected structurally (any block of *k* segments immediately repeated) so it
    holds for any app, rather than by hard-coding one target's doubled prefix.

    Args:
        path: URL path component.

    Returns:
        ``True`` when an adjacent segment-block repetition is present.
    """
    segments = [s for s in path.split("/") if s]
    total = len(segments)
    for size in range(1, total // 2 + 1):
        for start in range(total - 2 * size + 1):
            if segments[start : start + size] == segments[start + size : start + 2 * size]:
                return True
    return False


def path_extension(path: str) -> str:
    """The lowercase extension of *path*'s last segment, or ``""``."""
    last_segment = path.rsplit("/", 1)[-1]
    return last_segment.rsplit(".", 1)[-1].lower() if "." in last_segment else ""


# Conventional API path prefixes. A route under one of these is a data endpoint
# rather than a page: it answers with records, takes parameters structurally, and
# is where a modern application's whole attack surface lives. These are
# ecosystem conventions (the two prefixes every REST style guide names), not any
# application's own vocabulary.
API_PATH_PREFIXES: tuple[str, ...] = ("/api/", "/rest/", "/v1/", "/v2/", "/graphql")


def is_api_path(path: str) -> bool:
    """Whether *path* sits under a conventional API prefix."""
    lowered = (path or "").lower()
    normalised = lowered if lowered.endswith("/") else lowered + "/"
    return any(normalised.startswith(p) or p in normalised for p in API_PATH_PREFIXES)


def crawl_visit_priority(url: str) -> int:
    """How worth *opening* a discovered URL is — lower is visited earlier.

    Used to spend a fixed enrichment budget on the pages that can actually yield
    a form or a parameterised link, instead of on whichever URLs the crawler
    emitted first. Grades:

    * **0** — carries a query string already: a parameterised route, the highest-
      value thing a crawl can hand the planner.
    * **1** — a route under a conventional API prefix. On a single-page
      application this is the *entire* server-side surface: the HTML pages are
      one shell and every parameter the app takes is carried to an ``/api``
      route. Ranked with application pages rather than below them, because on an
      SPA target there are no application pages to rank below.
    * **2** — an ordinary application page (no extension, or a handler
      extension). This is where forms live.
    * **3** — a source/help viewer or other low-value page.
    * **4** — a documentation / translation artifact.
    * **5** — a static asset: no form, no link, nothing to enrich.
    * **6** — a doubled-path crawl artifact: not a route at all.

    Args:
        url: Absolute URL as discovered by the crawl.

    Returns:
        The visit-priority grade.
    """
    parsed = urlparse(url)
    path = parsed.path.lower()
    if has_repeated_path_block(path):
        return 6
    extension = path_extension(path)
    if extension in STATIC_ASSET_EXTENSIONS:
        return 5
    if extension in DOC_ASSET_EXTENSIONS:
        return 4
    if any(fragment in path for fragment in LOW_VALUE_PATH_FRAGMENTS):
        return 3
    if parsed.query:
        return 0
    if is_api_path(path):
        return 1
    return 2


#: Trailing artifacts left by reading a URL out of an ESCAPED payload. A React
#: Server Component flight payload carries ``"href":"/x"`` JSON-escaped inside a
#: ``<script>``, so a harvester that never unescapes it reads the escape itself
#: as part of the path. ``%5C`` is a URL-encoded backslash; a nesting level adds
#: another, which is why the same link arrives three times::
#:
#:     https://github.com/ptkvaibhav
#:     https://github.com/ptkvaibhav%5C
#:     https://github.com/ptkvaibhav%5C%5C%5C
#:
#: On the portfolio run 14 of 212 crawl candidates (6.6%) were these, and each
#: one spent a slot of an 80-visit budget that 132 candidates never reached.
_ESCAPE_ARTIFACT_SUFFIXES: tuple[str, ...] = ("%5c", "\\")


def crawl_dedup_key(url: str) -> str:
    """The identity of *url* as a crawl candidate — one link, one key.

    Strips the fragment, a trailing slash, and any trailing escape artifact
    (:data:`_ESCAPE_ARTIFACT_SUFFIXES`), so the three spellings above collapse to
    one candidate instead of consuming three visits.

    This is a **dedup key, not a rewrite**. The caller keeps one of the real
    URLs it was given rather than fetching a URL this function invented — a path
    segment genuinely ending in an encoded backslash is rare but legal, and
    fetching one directory up from it would be a request the target never
    offered us. When the clean spelling was discovered it is a strict prefix of
    every mangled one, so keeping the lexicographically smallest member of a
    group picks it; when only the mangled spelling exists, that is what gets
    opened, unchanged.

    Args:
        url: Absolute URL as discovered by the crawl.

    Returns:
        The dedup key, or ``""`` when nothing is left of the URL.
    """
    key = (url or "").split("#", 1)[0].rstrip("/")
    lowered = key.lower()
    while True:
        for suffix in _ESCAPE_ARTIFACT_SUFFIXES:
            if lowered.endswith(suffix):
                key = key[: -len(suffix)]
                lowered = lowered[: -len(suffix)]
                break
        else:
            break
    return key.rstrip("/")
