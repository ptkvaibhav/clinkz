"""Normalising CLI output before a semantic assertion.

Typer renders ``--help`` through Rich, and Rich decides whether to emit colour
from the environment. On a developer's terminal it does not (the
:class:`~typer.testing.CliRunner` stream is not a tty); on GitHub Actions it
does, because Rich treats ``GITHUB_ACTIONS`` as a colour-capable CI. The two
renderings are the same help text, but only one of them is a plain string.

The failure this exists to stop is specific and was live for every CI run since
the assertion was added: Rich styles a flag as two runs, so ``--target`` is
emitted as ``ESC[1;36m-ESC[0mESC[1;36m-targetESC[0m``. The literal ``--target``
is not a substring of that, and the test read as "the flag is missing from the
command" when the flag was there and only the bytes around it had changed.

**Why strip rather than disable colour.** Setting ``NO_COLOR`` (or
``TERM=dumb``, or Click's ``color=False``) would also make the assertion pass,
by removing the condition that breaks it — the coloured render path would then
never be exercised by any test again, and a genuine flag-mangling regression on
the path CI actually runs would stay green forever. Stripping normalises the
output and leaves the coloured path exercised, which is what these tests are
about: they assert on the MEANING of what the CLI printed, not on its bytes.

Every ``--help`` assertion in the suite has this exposure, not just the one that
was observed failing, so the normalisation lives here rather than inline.
"""

from __future__ import annotations

import re
from typing import Any, Final

#: Every escape sequence Rich can emit: CSI (``ESC[...m`` and cursor moves),
#: OSC (``ESC]...BEL`` / ``ESC]...ESC\``), and the two-character Fe escapes.
#: Deliberately wider than "SGR only" — a normaliser that misses a sequence
#: reintroduces exactly the failure it exists to prevent.
_ANSI_RE: Final = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")


def strip_ansi(text: str) -> str:
    """Return *text* with every ANSI escape sequence removed."""
    return _ANSI_RE.sub("", text)


def plain(result_or_text: Any) -> str:
    """The CLI's output as plain text, ready for a semantic assertion.

    Args:
        result_or_text: A :class:`click.testing.Result` (anything carrying an
            ``output`` attribute) or the output string itself.

    Returns:
        The output with ANSI escapes removed. Line breaks and spacing are left
        alone — collapsing them too would blur assertions that are *about*
        layout, such as ``"OUT : 10.10.10.1"``.
    """
    text = getattr(result_or_text, "output", result_or_text)
    return strip_ansi(str(text))


def flowed(result_or_text: Any) -> str:
    """:func:`plain`, with every run of whitespace collapsed to one space.

    For prose that Rich has hard-wrapped into a panel: a sentence in the help
    text is one sentence to a reader and several lines on disk, so an assertion
    about the sentence has to see it as one.
    """
    return " ".join(plain(result_or_text).split())


__all__ = ["flowed", "plain", "strip_ansi"]
