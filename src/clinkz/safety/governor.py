"""The engagement governor — rate, concurrency, kill switch, blocking, action log.

One object sits between the engagement and the network. Every outbound request
asks it for permission first (:meth:`EngagementGovernor.authorize`) and reports
back what came home (:meth:`EngagementGovernor.observe_response`). That single
seam is where the production rails live:

  * **Rate limit** — a shared token bucket across the whole engagement. A
    benchmark tolerates flooding; a production application does not.
  * **Concurrency cap** — a semaphore, so a fan-out phase cannot open forty
    sockets against a live app.
  * **Destructive refusal** — :mod:`clinkz.safety.destructive`, applied to every
    request rather than only to parsed HTML forms.
  * **Kill switch** — an in-process ``halt()`` and a filesystem sentinel
    (``outputs/<id>/HALT``) so a single command from another terminal stops the
    engagement.
  * **Blocking detection** — consecutive throttle/block responses trip a halt
    instead of continuing to hammer a target that is refusing us.
  * **Window hard stop** — the authorized window is re-checked on every request,
    not only at startup.
  * **Action log** — every state-changing request, sent or refused.

**The governor never raises from the data path.** It returns a
:class:`RequestDecision`; a refusal becomes an error-shaped tool output the
calling methodology already knows how to handle. Stopping the engagement is the
Orchestrator's job — it polls :attr:`EngagementGovernor.halted` and winds the
phases down cleanly so the report is still produced. Raising through twenty
layers of methodology code, each with its own ``except Exception``, would make
"halted" indistinguishable from "that probe failed".

**Absent by default.** :func:`get_active_governor` returns ``None`` unless an
engagement installed one, and every hook is written to no-op in that case. A
direct methodology invocation — a smoke test, a replay, a driver script — keeps
its existing behaviour byte for byte.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from clinkz.engagement.gate import EngagementAbortedError
from clinkz.models.engagement import EngagementWindow, SafetyPolicy
from clinkz.safety.action_log import CATEGORY_BROWSER_NAVIGATION, ActionLog
from clinkz.safety.benchmark import (
    benchmark_override,
    get_active_benchmark_profile,
    override_category,
)
from clinkz.safety.destructive import (
    MUTATING_METHODS,
    classify_request,
)

logger = logging.getLogger(__name__)

#: Filename of the kill-switch sentinel inside ``outputs/<engagement_id>/``.
HALT_SENTINEL = "HALT"

#: Reasons a governor halts. Recorded verbatim in the report.
HALT_KILL_SWITCH = "kill_switch"
HALT_WINDOW_CLOSED = "window_closed"
HALT_TARGET_BLOCKING = "target_blocking"
HALT_ACTION_CEILING = "state_change_ceiling"

#: Refusal categories the governor itself produces (as opposed to the
#: destructive classifier's categories).
REFUSED_HALTED = "engagement_halted"

#: Statuses that mean "throttled / refused by an edge" regardless of body.
_HARD_BLOCK_STATUSES = frozenset({429, 503})

#: Statuses that mean blocking only alongside a WAF signature — a bare 403 is
#: the correct answer to an authorization probe, and the IDOR class generates
#: them deliberately.
_SOFT_BLOCK_STATUSES = frozenset({401, 403, 406})

#: Body signatures for a block page. Deliberately tight: a false trip halts a
#: paid engagement, so a phrase must be one no ordinary application page emits.
_BLOCK_BODY_SIGNATURES = (
    "web application firewall",
    "request blocked",
    "you have been blocked",
    "attention required! | cloudflare",
    "incapsula incident id",
    "mod_security",
    "modsecurity",
    "access denied by",
    "blocked by security policy",
    "your request has been blocked",
)

#: Response headers whose presence identifies an edge/WAF vendor. Only counted
#: alongside a blocking status.
_WAF_HEADERS = ("cf-ray", "x-sucuri-id", "x-iinfo", "x-akamai-transformed", "x-waf-event")


class ResponseObserver(Protocol):
    """A watcher fed every response the engagement receives."""

    def __call__(
        self,
        status: int,
        headers: dict[str, str],
        body: str,
        *,
        session_bearing: bool = True,
    ) -> None:
        """Handle one response. Must be cheap and must not raise."""
        ...


class EngagementHaltedError(EngagementAbortedError):
    """Raised only by callers that choose to escalate a halted governor."""


class TargetBlockingDetectedError(EngagementAbortedError):
    """Raised only by callers that choose to escalate blocking detection."""


class RequestDecision(BaseModel):
    """The governor's answer to "may I send this?".

    Attributes:
        allowed: Whether the request may be sent.
        category: Why not, when refused.
        reason: One human sentence, suitable for a tool ``error`` field.
        signal: The deciding token/status, when there is one.
        state_changing: Whether this request mutates target state (logged either
            way — a refusal is as much a part of the record as a send).
    """

    model_config = ConfigDict(frozen=True)

    allowed: bool = True
    category: str = ""
    reason: str = ""
    signal: str = ""
    state_changing: bool = False


_ALLOWED_READ = RequestDecision()


class _TokenBucket:
    """Shared-rate token bucket with a one-second burst allowance.

    Args:
        rate: Sustained requests per second.
    """

    def __init__(self, rate: float) -> None:
        self._rate = max(rate, 0.01)
        self._capacity = max(1.0, self._rate)
        self._tokens = self._capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> float:
        """Consume one token, sleeping if necessary.

        Returns:
            Seconds spent waiting — reported so a slow engagement can be
            explained by its own rate limit rather than looking like a hang.
        """
        waited = 0.0
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(
                    self._capacity, self._tokens + (now - self._updated) * self._rate
                )
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return waited
                deficit = (1.0 - self._tokens) / self._rate
                waited += deficit
                await asyncio.sleep(deficit)


class EngagementGovernor:
    """Runtime safety rails for one engagement.

    Args:
        engagement_id: Engagement UUID — names the outputs directory and the
            kill-switch sentinel.
        policy: The configured :class:`~clinkz.models.engagement.SafetyPolicy`.
        window: Authorized window, re-checked on every request.
        outputs_root: Root directory holding per-engagement subdirectories.
    """

    def __init__(
        self,
        engagement_id: str,
        policy: SafetyPolicy | None = None,
        *,
        window: EngagementWindow | None = None,
        outputs_root: Path | str = Path("outputs"),
    ) -> None:
        self.engagement_id = engagement_id
        self.policy = policy or SafetyPolicy()
        self.window = window
        self.outputs_root = Path(outputs_root)
        self.action_log = ActionLog(engagement_id, outputs_root=self.outputs_root)

        self._bucket = _TokenBucket(self.policy.max_requests_per_second)
        self._slots = asyncio.Semaphore(self.policy.max_concurrent_requests)
        self._halted = False
        self._halt_reason = ""
        self._halt_detail = ""
        self._consecutive_blocks = 0
        self._state_changes_sent = 0
        self._requests_authorized = 0
        self._benchmark_permitted = 0
        self._rate_wait_seconds = 0.0
        # Extra watchers fed every response. The session sentinel registers here
        # rather than the governor importing it, which keeps the safety package
        # free of any dependency on the engagement's auth logic.
        self._observers: list[ResponseObserver] = []
        self._logger = logging.getLogger(f"{__name__}.EngagementGovernor")

    def add_response_observer(self, observer: ResponseObserver) -> None:
        """Register a callback fed every response the engagement receives.

        The callback is invoked as
        ``observer(status, headers, body, session_bearing=…)``. Used by the
        session sentinel: it needs to see every response the engagement
        receives, and no methodology can be relied on to report that it has been
        logged out — the code that lost the session is exactly the code that
        will not notice.

        ``session_bearing`` is the request seam's answer to "did this request
        actually carry the session?", which only the seam knows. An observer
        that had to guess would count the engagement's own anonymous controls as
        losses, which is precisely what it used to do.

        Args:
            observer: A cheap, non-raising callable. An exception from an
                observer is logged and swallowed; watching responses must never
                be able to break the request that produced them.
        """
        self._observers.append(observer)

    # ------------------------------------------------------------------
    # Kill switch
    # ------------------------------------------------------------------

    @property
    def halt_path(self) -> Path:
        """Path of the filesystem kill-switch sentinel."""
        return self.outputs_root / self.engagement_id / HALT_SENTINEL

    @property
    def halted(self) -> bool:
        """Whether the engagement has been halted (in-process or by sentinel)."""
        return self._halted

    @property
    def halt_reason(self) -> str:
        """Machine-readable halt reason; ``""`` when running."""
        return self._halt_reason

    @property
    def halt_detail(self) -> str:
        """Human-readable halt detail; ``""`` when running."""
        return self._halt_detail

    def halt(self, reason: str, detail: str = "") -> None:
        """Halt the engagement. Idempotent — the FIRST reason is the one kept.

        A later cause (say, blocking detection firing while the kill switch is
        already draining in-flight requests) must not overwrite the reason the
        operator will read in the report.

        Args:
            reason: One of the ``HALT_*`` constants.
            detail: Human-readable explanation for the report.
        """
        if self._halted:
            return
        self._halted = True
        self._halt_reason = reason
        self._halt_detail = detail
        self._logger.error("ENGAGEMENT HALTED (%s): %s", reason, detail or "(no detail)")

    def _check_kill_switch(self) -> None:
        """Trip the halt when the filesystem sentinel appears."""
        if self._halted:
            return
        try:
            if self.halt_path.exists():
                self.halt(
                    HALT_KILL_SWITCH,
                    f"Kill-switch sentinel present at {self.halt_path}",
                )
        except OSError:  # pragma: no cover — unreadable outputs dir
            pass

    def _check_window(self) -> None:
        """Trip the halt when the authorized window has closed."""
        if self._halted or self.window is None:
            return
        if self.window.has_ended():
            self.halt(
                HALT_WINDOW_CLOSED,
                f"Engagement window closed at {self.window.end.isoformat()}",
            )

    # ------------------------------------------------------------------
    # The request seam
    # ------------------------------------------------------------------

    async def authorize(
        self,
        method: str,
        url: str,
        *,
        body: str = "",
        stage: str = "",
        field_names: list[str] | None = None,
        labels: list[str] | None = None,
    ) -> RequestDecision:
        """Decide whether a request may be sent, and pace it if so.

        On an allowed request this consumes a rate-limit token and a concurrency
        slot; the caller MUST call :meth:`release` afterwards (or use
        :meth:`request`, which does it for you). On a refusal nothing is
        acquired, so a refused request costs no slot and no delay.

        Args:
            method: HTTP method.
            url: Request URL.
            body: Request body — parsed for field names, and excerpted into the
                action log.
            stage: Producing phase, for the action log.
            field_names: Explicit field names, when the caller already parsed them.
            labels: Button/label text associated with the action.

        Returns:
            A :class:`RequestDecision`. Never raises.
        """
        self._check_kill_switch()
        self._check_window()

        verb = (method or "GET").upper()
        names = list(field_names or []) or _body_field_names(body)

        if self._halted:
            decision = RequestDecision(
                allowed=False,
                category=REFUSED_HALTED,
                reason=f"Engagement halted ({self._halt_reason}): {self._halt_detail}",
                signal=self._halt_reason,
                state_changing=verb in MUTATING_METHODS,
            )
            self._log_refusal(decision, verb, url, body, stage)
            return decision

        verdict = classify_request(verb, url, field_names=names, labels=labels)
        # An engagement that declared its target a disposable benchmark may permit
        # named destructive categories. Applied AFTER classification, never inside
        # it: the classifier still names the category and the deciding signal, so
        # the action-log entry below can say exactly what was permitted and what
        # would otherwise have refused it. With no profile installed — every client
        # engagement — this is a no-op and the refusal below is unchanged.
        permitted_category = override_category(verdict)
        if permitted_category:
            self._benchmark_permitted += 1
            self.action_log.record_sent(
                method=verb,
                url=url,
                stage=stage,
                category=f"benchmark_permitted:{permitted_category}",
                reason=benchmark_override(verdict).reason,
                signal=verdict.signal,
                body=body,
            )
            verdict = benchmark_override(verdict)
        if verdict.refused:
            decision = RequestDecision(
                allowed=False,
                category=verdict.category,
                reason=verdict.reason,
                signal=verdict.signal,
                state_changing=True,
            )
            self._log_refusal(decision, verb, url, body, stage)
            return decision

        state_changing = verb in MUTATING_METHODS
        if state_changing and self.policy.max_state_changing_requests:
            if self._state_changes_sent >= self.policy.max_state_changing_requests:
                self.halt(
                    HALT_ACTION_CEILING,
                    (
                        f"Reached the configured ceiling of "
                        f"{self.policy.max_state_changing_requests} state-changing requests"
                    ),
                )
                decision = RequestDecision(
                    allowed=False,
                    category=HALT_ACTION_CEILING,
                    reason=self._halt_detail,
                    signal=str(self.policy.max_state_changing_requests),
                    state_changing=True,
                )
                self._log_refusal(decision, verb, url, body, stage)
                return decision

        self._rate_wait_seconds += await self._bucket.acquire()
        await self._slots.acquire()
        self._requests_authorized += 1
        if state_changing:
            self._state_changes_sent += 1
            self.action_log.record_sent(
                method=verb,
                url=url,
                stage=stage,
                category="mutating_method",
                reason=f"{verb} mutates target state",
                body=body,
            )
        if state_changing:
            return RequestDecision(allowed=True, state_changing=True)
        return _ALLOWED_READ

    def release(self) -> None:
        """Release the concurrency slot acquired by an allowed :meth:`authorize`."""
        self._slots.release()

    def record_navigation(
        self,
        *,
        outcome: str,
        method: str,
        url: str,
        stage: str = "",
        category: str = "",
        reason: str = "",
        signal: str = "",
        body: str = "",
    ) -> None:
        """Log one P7 browser navigation, allowed or refused.

        Separate from :meth:`authorize` rather than folded into it, because the
        two answer different questions. ``authorize`` decides whether a
        *request* may be sent and logs it only when it mutates — the right rule
        for a probe. A navigation is logged unconditionally: what is being
        recorded is that a real engine was pointed at the target and ran its
        code. An operator auditing "what did it do to my app" needs to see that
        whether the method was POST or GET.

        The tally is kept apart from the state-changing counters, so
        ``state_changing_sent`` never has to be read as "…plus some GETs".
        """
        self.action_log.record_navigation(
            outcome=outcome,
            method=method,
            url=url,
            stage=stage,
            category=category or CATEGORY_BROWSER_NAVIGATION,
            reason=reason,
            signal=signal,
            body=body,
        )

    def observe_response(
        self,
        *,
        status: int,
        headers: dict[str, str] | None = None,
        body: str = "",
        session_bearing: bool = True,
    ) -> None:
        """Feed a response back for blocking detection and session watching.

        Consecutive blocked responses trip the halt; any clean response resets
        the counter, so an isolated 403 from a working authorization control —
        exactly what the IDOR class produces on purpose — never trips it.

        Args:
            status: HTTP status code.
            headers: Response headers.
            body: Response body.
            session_bearing: Whether the originating request carried the
                engagement's session material. Passed straight through to the
                observers; blocking detection deliberately ignores it, because a
                WAF blocks anonymous and authenticated requests alike.
        """
        for observer in self._observers:
            try:
                observer(status, headers or {}, body, session_bearing=session_bearing)
            except Exception as exc:  # noqa: BLE001 — a watcher must never break a request
                self._logger.warning("Response observer raised: %s", exc)

        if self._halted:
            return
        if _looks_blocked(status, headers or {}, body):
            self._consecutive_blocks += 1
            self._logger.warning(
                "Target appears to be blocking us (status=%d, %d consecutive)",
                status,
                self._consecutive_blocks,
            )
            if (
                self.policy.halt_on_blocking
                and self._consecutive_blocks >= self.policy.blocking_threshold
            ):
                self.halt(
                    HALT_TARGET_BLOCKING,
                    (
                        f"{self._consecutive_blocks} consecutive blocked/throttled responses "
                        f"(latest status {status}) — stopping rather than continuing to "
                        "hammer a target that is refusing us"
                    ),
                )
        else:
            self._consecutive_blocks = 0

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, object]:
        """Runtime counters for the report and the run summary."""
        profile = get_active_benchmark_profile()
        return {
            "requests_authorized": self._requests_authorized,
            "state_changing_sent": self.action_log.sent_count,
            "state_changing_refused": self.action_log.refused_count,
            "browser_navigations": self.action_log.navigation_count,
            # Kept as its own counter rather than folded into
            # ``state_changing_sent``: "how many requests would have been refused
            # without the benchmark declaration" is the question an operator asks
            # when reviewing what the run was allowed to do, and a number that
            # needs qualifying is a number nobody trusts.
            "benchmark_permitted_requests": self._benchmark_permitted,
            "benchmark_profile_active": profile is not None,
            "benchmark_permitted_categories": (
                sorted(profile.permitted_categories) if profile else []
            ),
            "rate_limit_wait_seconds": round(self._rate_wait_seconds, 1),
            "max_requests_per_second": self.policy.max_requests_per_second,
            "max_concurrent_requests": self.policy.max_concurrent_requests,
            "halted": self._halted,
            "halt_reason": self._halt_reason,
            "halt_detail": self._halt_detail,
            "consecutive_blocks_at_end": self._consecutive_blocks,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _log_refusal(
        self,
        decision: RequestDecision,
        method: str,
        url: str,
        body: str,
        stage: str,
    ) -> None:
        """Record a refusal, but only for requests that could have mutated.

        A refused GET is ordinary crawl hygiene and would bury the record an
        operator actually needs. A refused mutation is the record.
        """
        if not decision.state_changing and decision.category != REFUSED_HALTED:
            return
        self.action_log.record_refused(
            method=method,
            url=url,
            stage=stage,
            category=decision.category,
            reason=decision.reason,
            signal=decision.signal,
            body=body,
        )


def _body_field_names(body: str) -> list[str]:
    """Extract field NAMES from a urlencoded or JSON request body.

    Names only — never values. A value is our payload, and reading our own
    payloads back as semantics is how a safety rail turns into a self-inflicted
    outage (see :data:`clinkz.safety.destructive._PLAIN_VALUE`).

    Args:
        body: Raw request body.

    Returns:
        Field names, or ``[]`` when the body is empty or unparseable.
    """
    if not body:
        return []
    stripped = body.lstrip()
    if stripped.startswith("{"):
        import json

        try:
            parsed = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            return []
        return [str(k) for k in parsed] if isinstance(parsed, dict) else []
    if "=" in body and "\n" not in body[:200]:
        from urllib.parse import parse_qsl

        try:
            return [k for k, _ in parse_qsl(body, keep_blank_values=True)]
        except ValueError:
            return []
    return []


def _looks_blocked(status: int, headers: dict[str, str], body: str) -> bool:
    """Whether a response reads as "the target is blocking us"."""
    if status in _HARD_BLOCK_STATUSES:
        return True

    lower_body = body[:4096].lower() if body else ""
    if any(sig in lower_body for sig in _BLOCK_BODY_SIGNATURES):
        return True

    if status in _SOFT_BLOCK_STATUSES:
        lower_headers = {k.lower(): (v or "").lower() for k, v in headers.items()}
        if any(h in lower_headers for h in _WAF_HEADERS):
            return True
        if "cloudflare" in lower_headers.get("server", ""):
            return True
    return False


# ---------------------------------------------------------------------------
# Active-governor registry — mirrors the TraceWriter pattern
# ---------------------------------------------------------------------------

_ACTIVE_GOVERNOR: EngagementGovernor | None = None


def set_active_governor(governor: EngagementGovernor | None) -> None:
    """Install (or clear) the governor every request seam consults.

    Args:
        governor: The engagement's governor, or ``None`` to uninstall.
    """
    global _ACTIVE_GOVERNOR
    _ACTIVE_GOVERNOR = governor


def get_active_governor() -> EngagementGovernor | None:
    """Return the installed governor, or ``None`` when the rails are absent."""
    return _ACTIVE_GOVERNOR


__all__ = [
    "HALT_ACTION_CEILING",
    "HALT_KILL_SWITCH",
    "HALT_SENTINEL",
    "HALT_TARGET_BLOCKING",
    "HALT_WINDOW_CLOSED",
    "REFUSED_HALTED",
    "EngagementGovernor",
    "EngagementHaltedError",
    "RequestDecision",
    "ResponseObserver",
    "TargetBlockingDetectedError",
    "get_active_governor",
    "set_active_governor",
]
