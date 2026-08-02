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


def crawl_visit_priority(url: str) -> int:
    """How worth *opening* a discovered URL is — lower is visited earlier.

    Used to spend a fixed enrichment budget on the pages that can actually yield
    a form or a parameterised link, instead of on whichever URLs the crawler
    emitted first. Grades:

    * **0** — carries a query string already: a parameterised route, the highest-
      value thing a crawl can hand the planner.
    * **1** — an ordinary application page (no extension, or a handler
      extension). This is where forms live.
    * **2** — a source/help viewer or other low-value page.
    * **3** — a documentation / translation artifact.
    * **4** — a static asset: no form, no link, nothing to enrich.
    * **5** — a doubled-path crawl artifact: not a route at all.

    Args:
        url: Absolute URL as discovered by the crawl.

    Returns:
        The visit-priority grade.
    """
    parsed = urlparse(url)
    path = parsed.path.lower()
    if has_repeated_path_block(path):
        return 5
    extension = path_extension(path)
    if extension in STATIC_ASSET_EXTENSIONS:
        return 4
    if extension in DOC_ASSET_EXTENSIONS:
        return 3
    if any(fragment in path for fragment in LOW_VALUE_PATH_FRAGMENTS):
        return 2
    if parsed.query:
        return 0
    return 1
