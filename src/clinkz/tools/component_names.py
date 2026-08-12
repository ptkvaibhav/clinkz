"""Splitting a fingerprint string into a component name and a version.

Every fingerprinting tool reports "what is running here" as prose, and each one
picks its own punctuation: ``nginx/1.24.0`` (a Server header), ``nginx:1.24.0``
(httpx ``-tech-detect``), ``Express 4.17.1`` (a banner), ``OpenSSH 8.9p1``
(nmap). Splitting that is the WRAPPER's job — it is the only code that knows
which tool's format it is holding — but the splitting RULE is one rule, so it
lives here rather than three times over.

The rule is deliberately conservative, because the consumer is a CVE lookup and
a wrong version is worse than no version. A trailing token becomes a version
only when it *looks* like one: a digit-led, dotted-or-suffixed token. Anything
else stays part of the name. ``Microsoft IIS`` keeps both words; ``PHP 8.1.2``
splits; ``Windows Server 2019`` — a year, not a version — is the case this
would get wrong, so a bare 4-digit token is refused as a version.
"""

from __future__ import annotations

import re

#: A version token: digit-led, and either dotted (``8.1``, ``1.24.0``) or
#: carrying a release suffix (``8.9p1``, ``2.4.49-1``, ``5.7.36rc2``). A bare
#: integer is NOT a version — ``Windows Server 2019`` and ``HTTP/2`` would both
#: acquire a fictional one, and a CVE lookup keyed on a fiction is worse than a
#: lookup that honestly has no version to key on.
_VERSION_RE = re.compile(
    r"^v?\d+(?:\.\d+)+(?:[.\-+~]?[A-Za-z0-9]+)*$"  # dotted: 8.1, 1.24.0, 2.4.49-1
    r"|^v?\d+[A-Za-z][A-Za-z0-9.\-]*$"  # digit-led with a suffix: 8p1, 5rc2
)

#: Separators a tool may put between a product and its version.
_SEPARATORS = ("/", ":", " ", "-")


def looks_like_version(token: str) -> bool:
    """Whether *token* is a version string rather than part of a product name."""
    return bool(_VERSION_RE.match((token or "").strip()))


def split_name_version(raw: str) -> tuple[str, str]:
    """Split a fingerprint string into ``(name, version)``.

    Args:
        raw: The tool's own rendering — ``"nginx/1.24.0"``, ``"Express 4.17.1"``,
            ``"jQuery"``, or ``""``.

    Returns:
        ``(name, version)``, with ``version`` empty whenever no trailing token
        looks like one. ``("", "")`` for empty input.

    Example::

        split_name_version("nginx/1.24.0")   # ("nginx", "1.24.0")
        split_name_version("Express 4.17.1") # ("Express", "4.17.1")
        split_name_version("jQuery")         # ("jQuery", "")
        split_name_version("Windows 2019")   # ("Windows 2019", "")
    """
    text = (raw or "").strip()
    if not text:
        return "", ""
    for sep in _SEPARATORS:
        if sep not in text:
            continue
        head, _, tail = text.rpartition(sep)
        head = head.strip()
        tail = tail.strip()
        if head and looks_like_version(tail):
            return head, tail
    return text, ""


__all__ = ["looks_like_version", "split_name_version"]
