"""Every out-of-scope target the engagement reached for, and refused.

A real application links out. A portfolio site links to GitHub and LinkedIn; a
SaaS app loads a CDN, a status page, an analytics beacon. The crawler follows
links because that is what a crawler does, and the scope check refuses the ones
that leave the authorised host. That refusal is the single most important
control in an external engagement — it is the difference between testing the
client and scanning a third party who never agreed to anything.

It was also, until this module, **completely silent**. ``ToolBase._check_scope``
raised a ``ValueError`` that the discovery fetch helper caught and turned into
``None``, and nothing anywhere recorded that the attempt had been made or
refused. So the deliverable could say "we stayed in scope" with exactly as much
evidence as a run that had no links to follow: none. An unenforced control and
a perfectly enforced one produced identical artifacts.

Why not the action log
----------------------

:mod:`clinkz.safety.action_log` deliberately records only refusals of
*state-changing* requests — "a refused GET is ordinary crawl hygiene and would
bury the record an operator actually needs". That reasoning is right and it is
about a different question. A destructive refusal answers "what did it do to my
app"; a scope refusal answers "did it touch anyone else". Different fixes,
different readers, so they stay apart — the same reason the contribution ledger
keeps its four alarm classes separate.

Absent by default, like the governor and the ledger, so a directly invoked
methodology is byte-identical.
"""

from __future__ import annotations

import logging
import threading
from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

#: Most refusals to retain in full. A crawler that finds a paginated index of
#: 40,000 external links must not turn the record into the artifact. The COUNT
#: stays exact past this — a truncated tally would be the silent-cap failure
#: this module exists to prevent.
MAX_RETAINED = 500


@dataclass(frozen=True)
class ScopeRefusal:
    """One attempt to reach a target outside the engagement scope.

    Attributes:
        target: What was asked for, verbatim. The whole point of the record.
        host: The host it resolved to, for the by-host tally.
        stage: Which phase reached for it.
        tool: The tool wrapper that refused, when known.
    """

    target: str
    host: str
    stage: str = ""
    tool: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"target": self.target, "host": self.host, "stage": self.stage, "tool": self.tool}


def _host_of(target: str) -> str:
    """Best-effort host for the tally. Never raises — this is a log, not a gate."""
    candidate = target.strip()
    try:
        parsed = urlparse(candidate if "//" in candidate else f"//{candidate}")
        return (parsed.hostname or candidate).lower()
    except ValueError:
        return candidate.lower()


@dataclass
class ScopeRefusalLog:
    """Every out-of-scope attempt this engagement made, and refused."""

    _refusals: list[ScopeRefusal] = field(default_factory=list)
    _hosts: Counter[str] = field(default_factory=Counter)
    _total: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, target: str, *, stage: str = "", tool: str = "") -> None:
        """Record one refusal. Always — a refusal nobody logged did not happen."""
        host = _host_of(target)
        with self._lock:
            self._total += 1
            self._hosts[host] += 1
            if len(self._refusals) < MAX_RETAINED:
                self._refusals.append(
                    ScopeRefusal(target=target, host=host, stage=stage, tool=tool)
                )
        logger.info("OUT OF SCOPE, refused: %s (host=%s, stage=%s)", target, host, stage or "-")

    def refusals(self) -> list[ScopeRefusal]:
        """The retained refusals, in the order they happened."""
        with self._lock:
            return list(self._refusals)

    @property
    def total(self) -> int:
        """How many refusals happened. Exact, even past :data:`MAX_RETAINED`."""
        with self._lock:
            return self._total

    def hosts(self) -> dict[str, int]:
        """Refusals per out-of-scope host, most-refused first."""
        with self._lock:
            return dict(self._hosts.most_common())

    def to_dict(self) -> dict[str, Any]:
        """Render for the report.

        Rendered even when empty, because "nothing out of scope was reached
        for" is a claim worth making explicitly. A section that appears only
        when something happened cannot be told apart from one nobody wrote —
        which is exactly the state this module replaces.
        """
        with self._lock:
            total = self._total
            retained = list(self._refusals)
            hosts = dict(self._hosts.most_common())
        return {
            "total_refused": total,
            "out_of_scope_hosts": hosts,
            "retained": len(retained),
            "truncated": total > len(retained),
            "refusals": [r.to_dict() for r in retained],
        }

    def log_summary(self, log: logging.Logger) -> None:
        """Report the control's outcome at the end of the run."""
        total = self.total
        if not total:
            log.info(
                "Scope control: no out-of-scope target was reached for. Every request "
                "stayed inside the authorised scope."
            )
            return
        log.warning(
            "Scope control: %d out-of-scope attempt(s) REFUSED across %d host(s): %s",
            total,
            len(self.hosts()),
            ", ".join(f"{h} x{n}" for h, n in self.hosts().items()),
        )


# ---------------------------------------------------------------------------
# The active log — absent by default
# ---------------------------------------------------------------------------

_active_log: ScopeRefusalLog | None = None


def set_active_scope_refusal_log(log: ScopeRefusalLog | None) -> None:
    """Install (or clear) the engagement's scope-refusal log."""
    global _active_log
    _active_log = log


def get_active_scope_refusal_log() -> ScopeRefusalLog | None:
    """The engagement's scope-refusal log, or ``None``."""
    return _active_log


def record_scope_refusal(target: str, *, stage: str = "", tool: str = "") -> None:
    """Record an out-of-scope refusal against the active log, if there is one.

    Never raises. This is called from inside a scope check that is about to
    raise its own error, and a logging failure must not replace it.
    """
    log = _active_log
    if log is None:
        return
    try:
        log.record(target, stage=stage, tool=tool)
    except Exception:  # noqa: BLE001 — a record must never displace the refusal
        logger.debug("Could not record scope refusal for %s", target, exc_info=True)


def scope_refusal_summary() -> dict[str, Any]:
    """The active log's summary, or the empty shape when none is installed."""
    log = _active_log
    if log is None:
        return ScopeRefusalLog().to_dict()
    return log.to_dict()


__all__ = [
    "MAX_RETAINED",
    "ScopeRefusal",
    "ScopeRefusalLog",
    "get_active_scope_refusal_log",
    "record_scope_refusal",
    "scope_refusal_summary",
    "set_active_scope_refusal_log",
]
