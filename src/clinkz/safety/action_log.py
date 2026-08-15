"""Per-run action log — the answer to "what did it do to my app?".

An autonomous engagement against a production application has to be able to
account for itself afterwards, request by request. This module records every
**state-changing** request the engagement produced, in two flavours:

  * ``sent`` — a mutating request that actually went out, with its method, URL,
    a bounded excerpt of its body, and the status that came back.
  * ``refused`` — a mutating request the destructive classifier blocked, with the
    category and the exact signal that decided it.

Recording refusals alongside sends is what makes the log *checkable* rather than
merely informative: "no destructive request was sent" is provable by reading the
log, and every refusal is auditable back to the token that caused it — so a
false refusal can be argued with instead of silently costing coverage.

Read-only requests are deliberately NOT logged. The trace
(``outputs/<id>/trace.jsonl``) already records every request; this file answers a
narrower and more urgent question, and burying twelve mutations in forty
thousand GETs would defeat it.

Every record passes through :func:`clinkz.engagement.secrets.redact_structure`
before it is written.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from clinkz.config import outputs_root as configured_outputs_root
from clinkz.engagement.secrets import redact, redact_structure

logger = logging.getLogger(__name__)

#: Longest body excerpt kept per record. Enough to identify what was submitted,
#: bounded so a file upload cannot inflate the log.
_BODY_EXCERPT_LIMIT = 512

OUTCOME_SENT = "sent"
OUTCOME_REFUSED = "refused"
OUTCOME_FAILED = "failed"

#: Category stamped on every P7 browser navigation.
#:
#: A browser navigation is logged even when the method is GET, which is a
#: deliberate exception to the "only mutations are recorded" rule below. The
#: reason is that the thing being recorded is not the request — it is handing a
#: page to an engine that will *run the target's code*, fetch its subresources,
#: and follow whatever it is told to. "What did it do to my app?" is answered
#: wrongly by a log in which that does not appear.
CATEGORY_BROWSER_NAVIGATION = "browser_navigation"


class ActionRecord(BaseModel):
    """One state-changing request the engagement produced.

    Attributes:
        seq: Monotonic sequence number within the engagement.
        ts: ISO-8601 UTC timestamp.
        outcome: ``sent`` | ``refused`` | ``failed``.
        method: HTTP method.
        url: Request URL.
        stage: Which phase produced it (``recon`` / ``scan`` / ``exploit`` / …).
        category: Destructive category when refused; the reason it counted as
            state-changing when sent.
        reason: One human sentence.
        signal: The token or method that decided a refusal.
        status_code: Response status for a sent request; ``0`` otherwise.
        body_excerpt: Bounded, redacted excerpt of the request body.
        body_sha256: Digest of the FULL body, so two records can be compared
            even when both excerpts are truncated at the same point.
    """

    seq: int
    ts: str
    outcome: str
    method: str
    url: str
    stage: str = ""
    category: str = ""
    reason: str = ""
    signal: str = ""
    status_code: int = 0
    body_excerpt: str = ""
    body_sha256: str = ""


class ActionLog:
    """Append-only JSONL log of state-changing requests for one engagement.

    Thread-safe and cheap: a lock around a sequence counter and an append. The
    file is opened per write rather than held open, so a killed engagement
    leaves a complete, readable log rather than a truncated buffer — which is
    exactly the case an operator most needs it in.

    Args:
        engagement_id: Engagement UUID; names the output directory.
        outputs_root: Root directory holding per-engagement subdirectories.
    """

    def __init__(self, engagement_id: str, outputs_root: Path | str | None = None) -> None:
        self.engagement_id = engagement_id
        root = Path(outputs_root or configured_outputs_root())
        self.path = root / engagement_id / "actions.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = 0
        self._counts: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record(
        self,
        *,
        outcome: str,
        method: str,
        url: str,
        stage: str = "",
        category: str = "",
        reason: str = "",
        signal: str = "",
        status_code: int = 0,
        body: str = "",
        counter_key: str | None = None,
    ) -> ActionRecord:
        """Append one record and return it.

        Args:
            outcome: ``sent`` | ``refused`` | ``failed``.
            method: HTTP method.
            url: Request URL.
            stage: Producing phase.
            category: Destructive category, or why this counted as mutating.
            reason: One human sentence.
            signal: Deciding token/method for a refusal.
            status_code: Response status, for a sent request.
            body: Full request body; excerpted and digested, never stored whole.
            counter_key: Which tally this record increments. Defaults to
                *outcome*. Browser navigations pass their own key so that
                :attr:`sent_count` keeps meaning "state-changing requests sent"
                — a GET navigation belongs in the log but not in that number.

        Returns:
            The :class:`ActionRecord` as written.
        """
        with self._lock:
            self._seq += 1
            seq = self._seq
            key = counter_key or outcome
            self._counts[key] = self._counts.get(key, 0) + 1

        record = ActionRecord(
            seq=seq,
            ts=datetime.now(UTC).isoformat(),
            outcome=outcome,
            method=(method or "GET").upper(),
            url=redact(url),
            stage=stage,
            category=category,
            reason=reason,
            signal=signal,
            status_code=status_code,
            body_excerpt=redact(body[:_BODY_EXCERPT_LIMIT]) if body else "",
            body_sha256=(
                hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest() if body else ""
            ),
        )

        payload = redact_structure(record.model_dump())
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except OSError as exc:  # pragma: no cover — disk failure
            logger.warning("Could not append to action log %s: %s", self.path, exc)
        return record

    def record_sent(self, **kwargs: object) -> ActionRecord:
        """Record a state-changing request that was actually sent."""
        return self.record(outcome=OUTCOME_SENT, **kwargs)  # type: ignore[arg-type]

    def record_refused(self, **kwargs: object) -> ActionRecord:
        """Record a state-changing request the safety rails refused."""
        return self.record(outcome=OUTCOME_REFUSED, **kwargs)  # type: ignore[arg-type]

    def record_navigation(self, *, outcome: str, **kwargs: object) -> ActionRecord:
        """Record one P7 browser navigation — attempted, or refused before it ran.

        Every navigation, not only a mutating one: see
        :data:`CATEGORY_BROWSER_NAVIGATION`. The record lands in the same file
        an operator already reads, and its tally is kept apart from the
        state-changing counts so neither number has to be qualified.

        Args:
            outcome: ``sent`` for a navigation the rails allowed, ``refused``
                for one they stopped.
            **kwargs: As :meth:`record`; ``category`` defaults to the browser
                navigation category and a refusal may override it with the
                category that decided it.
        """
        kwargs.setdefault("category", CATEGORY_BROWSER_NAVIGATION)
        return self.record(
            outcome=outcome,
            counter_key=f"navigation_{outcome}",
            **kwargs,  # type: ignore[arg-type]
        )

    # ------------------------------------------------------------------
    # Reading back
    # ------------------------------------------------------------------

    @property
    def sent_count(self) -> int:
        """How many state-changing requests were actually sent."""
        return self._counts.get(OUTCOME_SENT, 0)

    @property
    def refused_count(self) -> int:
        """How many were refused by the safety rails."""
        return self._counts.get(OUTCOME_REFUSED, 0)

    @property
    def navigation_count(self) -> int:
        """How many browser navigations were logged, allowed and refused."""
        return self._counts.get(f"navigation_{OUTCOME_SENT}", 0) + self._counts.get(
            f"navigation_{OUTCOME_REFUSED}", 0
        )

    def summary(self) -> dict[str, int]:
        """Counts by outcome — for the report and the run summary."""
        return dict(self._counts)

    @staticmethod
    def read(
        engagement_id: str,
        outputs_root: Path | str | None = None,
    ) -> list[ActionRecord]:
        """Read a previously written action log back into records.

        Args:
            engagement_id: Engagement UUID.
            outputs_root: Root directory holding per-engagement subdirectories.

        Returns:
            Every parseable record, in file order. Missing file ⇒ ``[]``.
        """
        root = Path(outputs_root or configured_outputs_root())
        path = root / engagement_id / "actions.jsonl"
        if not path.is_file():
            return []
        records: list[ActionRecord] = []
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(ActionRecord.model_validate_json(line))
                except Exception as exc:  # noqa: BLE001 — a bad line must not hide good ones
                    logger.warning("Skipping unparseable action-log line: %s", exc)
        return records


class RefusalTally(BaseModel):
    """Per-category count of refused actions, for the report's "not tested".

    Attributes:
        by_category: Destructive category → how many requests it refused.
        examples: Destructive category → one representative ``METHOD URL``.
    """

    by_category: dict[str, int] = Field(default_factory=dict)
    examples: dict[str, str] = Field(default_factory=dict)

    @classmethod
    def from_records(cls, records: list[ActionRecord]) -> RefusalTally:
        """Build a tally from action-log records."""
        by_category: dict[str, int] = {}
        examples: dict[str, str] = {}
        for rec in records:
            if rec.outcome != OUTCOME_REFUSED:
                continue
            key = rec.category or "unclassified"
            by_category[key] = by_category.get(key, 0) + 1
            examples.setdefault(key, f"{rec.method} {rec.url}")
        return cls(by_category=by_category, examples=examples)


__all__ = [
    "CATEGORY_BROWSER_NAVIGATION",
    "OUTCOME_FAILED",
    "OUTCOME_REFUSED",
    "OUTCOME_SENT",
    "ActionLog",
    "ActionRecord",
    "RefusalTally",
]
