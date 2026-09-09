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
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict

from clinkz.config import outputs_root as configured_outputs_root
from clinkz.engagement.gate import EngagementAbortedError
from clinkz.models.engagement import EngagementWindow, SafetyPolicy
from clinkz.safety.action_log import (
    CATEGORY_BROWSER_NAVIGATION,
    CATEGORY_CREDENTIAL_ATTEMPT,
    ActionLog,
)
from clinkz.safety.benchmark import (
    benchmark_override,
    get_active_benchmark_profile,
    override_category,
)
from clinkz.safety.destructive import (
    MUTATING_METHODS,
    classify_request,
)
from clinkz.safety.lockout import NO_LOCKOUT, LockoutSignal, classify_lockout

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
#: The per-account credential-attempt budget is spent. Refusing here is the
#: whole point: a login path that keeps going is one that locks the account the
#: client handed us.
REFUSED_CREDENTIAL_BUDGET = "credential_attempt_budget"
#: The target already told us it is not evaluating credentials any more —
#: locked, throttled or behind a human-verification gate. Every further attempt
#: is a request we know the answer to and a harm we choose to cause.
REFUSED_CREDENTIAL_STOPPED = "credential_attempts_stopped"

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
        outputs_root: Path | str | None = None,
    ) -> None:
        self.engagement_id = engagement_id
        self.policy = policy or SafetyPolicy()
        self.window = window
        self.outputs_root = Path(outputs_root or configured_outputs_root())
        self.action_log = ActionLog(engagement_id, outputs_root=self.outputs_root)

        self._bucket = _TokenBucket(self.policy.max_requests_per_second)
        self._slots = asyncio.Semaphore(self.policy.max_concurrent_requests)
        self._halted = False
        self._halt_reason = ""
        self._halt_detail = ""
        self._consecutive_blocks = 0
        # Block-page signatures this target served in a response that was NOT
        # blocked. The control for the body arm of blocking detection, sourced
        # from responses the engagement already holds so the rail never
        # dispatches traffic of its own. Grows monotonically: a marker proved
        # benign once stays benign, because the proof is about the target's
        # vocabulary and that does not un-happen.
        self._benign_markers: set[str] = set()
        self._state_changes_sent = 0
        self._requests_authorized = 0
        # The engagement's REQUEST window, stamped here because this is the one
        # place that sees every dispatched request. The report used to source
        # its "testing performed" line from the report-generation clock, so both
        # ends were the same instant and a run of 4,597s rendered as zero —
        # directly under the authorized window, where that line is the report's
        # own evidence that testing happened inside it.
        self._first_request_at: datetime | None = None
        self._last_request_at: datetime | None = None
        self._benchmark_permitted = 0
        self._rate_wait_seconds = 0.0
        # Extra watchers fed every response. The session sentinel registers here
        # rather than the governor importing it, which keeps the safety package
        # free of any dependency on the engagement's auth logic.
        self._observers: list[ResponseObserver] = []
        # Credential attempts, counted per (origin, account). Not per call, not
        # per engagement: the harm is "how many times did we offer a password
        # for THIS account", and that number is spread across three producers
        # that never spoke to each other — the login, the session refresh, and
        # the default-credential sweep, each constructing its own authenticator.
        # The governor is the one object all three already pass through.
        self._credential_attempts: dict[tuple[str, str], int] = {}
        self._credential_stops: dict[tuple[str, str], LockoutSignal] = {}
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
        account: str = "",
        credential_reserve: bool = False,
    ) -> RequestDecision:
        """Decide whether a request may be sent, and pace it if so.

        On an allowed request this consumes a rate-limit token and a concurrency
        slot; the caller MUST call :meth:`release` afterwards (or use
        :meth:`request`, which does it for you). On a refusal nothing is
        acquired, so a refused request costs no slot and no delay.

        **A credential-bearing request names the account it is offering a
        password for**, and that is the only way this object can bound a
        brute-force it did not intend to perform. The authenticator used to take
        ONE slot for a whole ``authenticate()`` call — the login-page GET, both
        attempts, the 415 re-POST and every redirect hop inside it — so the
        component that owns the rate limit, the action log and the kill switch
        saw a single "POST /login" where sixteen credential POSTs had gone out.
        Naming the account moves the slot to the POST and gives the count
        somewhere to live.

        Args:
            method: HTTP method.
            url: Request URL.
            body: Request body — parsed for field names, and excerpted into the
                action log.
            stage: Producing phase, for the action log.
            field_names: Explicit field names, when the caller already parsed them.
            labels: Button/label text associated with the action.
            account: The account identifier this request offers a credential
                for. Non-empty marks the request a credential attempt: it is
                counted against :attr:`SafetyPolicy.max_credential_attempts_per_account`
                and refused once that budget is spent or once the target has
                shown us it stopped evaluating credentials. Empty — every other
                request in the engagement — is byte-identical to before.
            credential_reserve: Whether this attempt may spend the share held
                back by :attr:`SafetyPolicy.adaptive_auth_credential_reserve`.
                False — the deterministic login pass, and everything else — is
                refused once the unreserved share is gone. Only the adaptive
                layer sets it, because it is the only consumer that runs after
                another one has already spent from the same account.

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

        if account:
            credential_refusal = self._credential_decision(verb, url, account, credential_reserve)
            if credential_refusal is not None:
                self._log_refusal(credential_refusal, verb, url, body, stage)
                return credential_refusal

        self._rate_wait_seconds += await self._bucket.acquire()
        await self._slots.acquire()
        if account:
            self._credential_attempts[self._credential_key(url, account)] = (
                self._credential_attempts.get(self._credential_key(url, account), 0) + 1
            )
        self._requests_authorized += 1
        self._stamp_request_window()
        if state_changing:
            self._state_changes_sent += 1
            spent = self._credential_attempts.get(self._credential_key(url, account), 0)
            self.action_log.record_sent(
                method=verb,
                url=url,
                stage=stage,
                # A credential attempt is named as one. It is a state-changing
                # request like any other, but "POST mutates target state" is
                # what the log said for all sixteen of them, and an operator
                # asking "how many times did you try my admin password" could
                # not answer it from the client-facing record.
                category=CATEGORY_CREDENTIAL_ATTEMPT if account else "mutating_method",
                reason=(
                    f"credential attempt {spent} of "
                    f"{self.policy.max_credential_attempts_per_account} for account "
                    f"{account!r} at {_origin(url)}"
                    if account
                    else f"{verb} mutates target state"
                ),
                signal=account,
                body=body,
            )
            return RequestDecision(allowed=True, state_changing=True)
        return _ALLOWED_READ

    def release(self) -> None:
        """Release the concurrency slot acquired by an allowed :meth:`authorize`."""
        self._slots.release()

    # ------------------------------------------------------------------
    # Credential attempts
    # ------------------------------------------------------------------

    @staticmethod
    def _credential_key(url: str, account: str) -> tuple[str, str]:
        """The budget key: origin plus account.

        Origin, not URL. The JSON arm walks up to eight ROUTES on one host,
        offering the same password to the same account each time; a per-URL
        counter would give each route its own budget and would bound nothing.
        Account, not role: the sweep tries four passwords for ``admin`` under
        four different technology labels, and the account is what locks.
        """
        return (_origin(url), account)

    def _credential_decision(
        self, verb: str, url: str, account: str, reserved: bool = False
    ) -> RequestDecision | None:
        """Refuse a credential attempt that is spent or already answered, else ``None``.

        Two refusals, and they are different facts:

        * **Stopped.** The target has already told us it is not evaluating
          credentials — locked, throttled, or gated behind human verification.
          Every further attempt is a request whose answer we already have, and
          on a lockout it is a request that extends the lock. Checked FIRST,
          because it is an observation about the target and the budget is only
          an assumption about it.
        * **Budget spent.** We have offered this account
          :attr:`SafetyPolicy.max_credential_attempts_per_account` passwords and
          none of them worked. Production policies trip between three and ten
          attempts, so the alternative to refusing here is locking an account
          the client handed us on the assumption that we would be careful.

        Args:
            verb: HTTP method, for the refusal's ``state_changing`` flag.
            url: Where the credential would go.
            account: Which account it is for.
            reserved: Whether this caller may spend the adaptive-auth reserve.

        Returns:
            The refusal, or ``None`` when the attempt may proceed.
        """
        key = self._credential_key(url, account)

        stop = self._credential_stops.get(key)
        if stop and stop.kind is not None:
            return RequestDecision(
                allowed=False,
                category=REFUSED_CREDENTIAL_STOPPED,
                reason=(
                    f"the login at {key[0]} already answered with {stop.kind.value} "
                    f"({stop.detail}: {stop.marker!r}) for account {account!r}. That answer "
                    f"was not about the password, so offering another one tells us nothing "
                    f"and, on a lockout, extends it"
                ),
                signal=stop.marker,
                state_changing=verb in MUTATING_METHODS,
            )

        budget = self._budget_for(reserved)
        spent = self._credential_attempts.get(key, 0)
        if budget and spent >= budget:
            reserve = self._reserve()
            held = (
                ""
                if reserved or not reserve
                else (
                    f" ({reserve} of the {self.policy.max_credential_attempts_per_account} "
                    f"are held back for the adaptive layer, which is the only consumer "
                    f"that runs after this one and would otherwise never get a turn)"
                )
            )
            return RequestDecision(
                allowed=False,
                category=REFUSED_CREDENTIAL_BUDGET,
                reason=(
                    f"{spent} credential attempts have been made against account "
                    f"{account!r} at {key[0]} and this caller's budget is {budget}{held}. "
                    f"Refusing further attempts. If this login genuinely needs more, "
                    f"declare login_api_url / login_field / login_content_type so it is "
                    f"reached in one, or raise max_credential_attempts_per_account"
                ),
                signal=str(budget),
                state_changing=verb in MUTATING_METHODS,
            )
        return None

    def _reserve(self) -> int:
        """Attempts held back from the deterministic pass, never exceeding the budget.

        A reserve larger than the allowance would starve the deterministic pass
        instead — the same defect pointing the other way — so it is clamped
        rather than trusted, and clamped to ``budget - 1`` so the unreserved
        share is never zero.
        """
        budget = self.policy.max_credential_attempts_per_account
        reserve = max(0, self.policy.adaptive_auth_credential_reserve)
        if not budget:
            return 0
        return min(reserve, max(0, budget - 1))

    def _budget_for(self, reserved: bool) -> int:
        """This caller's share of the per-account allowance.

        ``0`` still means unbounded, as it always has: an unset allowance has no
        share to divide, so a reserve against it would be a bound invented out
        of a policy that declined to set one.
        """
        budget = self.policy.max_credential_attempts_per_account
        if not budget:
            return 0
        return budget if reserved else budget - self._reserve()

    def credential_attempts_remaining(
        self, url: str, account: str, *, reserved: bool = False
    ) -> int | None:
        """How many more credentials may be offered to *account* at *url*'s origin.

        Read by a caller that has to DECIDE something before dispatching rather
        than be refused at dispatch — the adaptive-auth loop, which must know
        whether it can afford a credential POST before it proposes one, because
        proposing one it cannot afford spends a turn and teaches nothing.

        **A recorded stop returns zero, ahead of the arithmetic.** The target
        telling us it has stopped evaluating credentials outranks a budget we
        assumed (invariant 92): a caller reading "two attempts left" against a
        locked account would be reading a number that is arithmetically true and
        operationally false, and :meth:`_credential_decision` would refuse the
        request anyway. Answering the same way in both places is what keeps a
        pre-flight check from disagreeing with the gate it is checking.

        Args:
            url: Any URL on the origin the credential would go to.
            account: The account identifier.
            reserved: Whether the asking caller may spend the adaptive-auth
                reserve. The adaptive loop asks with ``True``, which is the
                whole reason it can get a non-zero answer after the
                deterministic pass has spent its own share.

        Returns:
            Attempts remaining, where ``0`` means the next one will be refused,
            or ``None`` when this policy configures no per-account bound at all.
            ``None`` rather than a large number: a caller that has to branch on
            "is there a bound" must not be handed a bound-shaped value it will
            print, and ``max_credential_attempts_per_account = 0`` is how
            :meth:`_credential_decision` already spells *unbounded*.
        """
        key = self._credential_key(url, account)
        stop = self._credential_stops.get(key)
        if stop and stop.kind is not None:
            return 0
        if not self.policy.max_credential_attempts_per_account:
            return None
        return max(0, self._budget_for(reserved) - self._credential_attempts.get(key, 0))

    def observe_credential_response(
        self,
        *,
        url: str,
        account: str,
        status: int,
        headers: dict[str, str] | None = None,
        body: str = "",
        control_body: str = "",
    ) -> LockoutSignal:
        """Read one login response for evidence that further attempts are pointless.

        Recorded, not raised. The authenticator asks :meth:`authorize` before
        the next attempt and is refused there, which keeps the "never raises
        from the data path" rule intact and keeps the refusal in the action log
        beside every other one.

        Only the FIRST signal per account is kept. A second would overwrite the
        observation that actually stopped us with whatever the target said
        afterwards, and the first is the one the operator needs to see.

        Args:
            url: The URL the credential went to.
            account: The account the credential was for.
            status: Response status.
            headers: Response headers.
            body: Response body.
            control_body: The same page served without a credential, when the
                caller holds one. Phrases present in both are discarded rather
                than allowed to stop the run — see
                :func:`~clinkz.safety.lockout.classify_lockout`.

        Returns:
            The :class:`~clinkz.safety.lockout.LockoutSignal` — falsy when the
            response carried none.
        """
        if not account:
            return NO_LOCKOUT
        signal = classify_lockout(status, headers, body, control_body)
        if signal.discarded:
            # A discard is not a stop, and it is not nothing either: it is the
            # run declining to halt on words the login page was already serving.
            self._logger.info(
                "Lockout phrases %s appear in the credential response for %r at %s AND in "
                "the control, so they are not evidence about this account; not stopping.",
                ", ".join(repr(d) for d in signal.discarded),
                account,
                url,
            )
        if not signal:
            return NO_LOCKOUT
        key = self._credential_key(url, account)
        if key not in self._credential_stops:
            self._credential_stops[key] = signal
            self._logger.error(
                "CREDENTIAL STOP for %r at %s: %s (%s: %r). No further credential will be "
                "offered for this account.",
                account,
                key[0],
                signal.kind.value if signal.kind else "",
                signal.detail,
                signal.marker,
            )
        return signal

    def credential_attempts(self, url: str, account: str) -> int:
        """How many credential attempts this engagement has made for one account."""
        return self._credential_attempts.get(self._credential_key(url, account), 0)

    def credential_stop(self, url: str, account: str) -> LockoutSignal:
        """The recorded stop for one account, or ``NO_LOCKOUT``."""
        return self._credential_stops.get(self._credential_key(url, account), NO_LOCKOUT)

    def first_credential_stop(self) -> tuple[str, LockoutSignal]:
        """The first stop recorded for ANY account, as ``(account, signal)``.

        The default-credential sweep asks this rather than asking per account,
        because a lockout / rate limit / captcha is usually a statement about
        the SOURCE or the endpoint rather than about one identity: an engine
        that stops guessing ``admin``'s password and carries straight on to
        ``root``'s has learned nothing from the evidence it just received.
        """
        for (_origin_, account), signal in self._credential_stops.items():
            if signal.kind is not None:
                return (account, signal)
        return ("", NO_LOCKOUT)

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
        self._learn_benign_markers(status, headers or {}, body)
        if _looks_blocked(status, headers or {}, body, self._benign_block_markers()):
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
                # A halt is an ABSENCE-GENERATING event. Every methodology
                # downstream of this point registers NEVER INVOKED in the
                # ledger, and a report assembled from those rows reads as an
                # engine that looked and found nothing — not as a run that was
                # stopped. That is what a false trip costs: on cal.diy it cost
                # 29 classes, and the deliverable said nothing about why. So
                # the body arm above is controlled, and the reason recorded
                # here is what the run-completion banner and the reachability
                # predicates must be read against.
                self.halt(
                    HALT_TARGET_BLOCKING,
                    (
                        f"{self._consecutive_blocks} consecutive blocked/throttled responses "
                        f"(latest status {status}) — stopping rather than continuing to "
                        "hammer a target that is refusing us. Every class not yet "
                        "dispatched is UNTESTED, not clean"
                    ),
                )
        else:
            self._consecutive_blocks = 0

    def _benign_block_markers(self) -> frozenset[str]:
        """Block signatures this target served in a response that was not blocked."""
        return frozenset(self._benign_markers)

    def _learn_benign_markers(self, status: int, headers: dict[str, str], body: str) -> None:
        """Record signatures carried by a response that is not itself blocked.

        The control the body arm needs is a response we ALREADY HOLD — recon's
        root fetch, the login GET, any prior success — so learning it costs no
        dispatch. A response qualifies only when nothing independent of the
        body says it was refused: a success status, and no WAF header. Both
        halves matter. A soft-blocking WAF that answers 200 with its own block
        page would otherwise teach us that its block page is normal, which is
        the one way this control could disarm the rail it is protecting.

        **Learning runs before the verdict, deliberately.** The alternative —
        judge, then learn — makes the halt depend on which response arrived
        first, and the crawl is concurrent, so it emits a different sequence
        every run. The cost is that a 200 carrying a block phrase and no WAF
        header of any kind is never read as a block. That response is
        indistinguishable from an application that ships the phrase, the
        target served it successfully, and a false halt is the expensive
        error: it is absence-generating, and the classes it skips render as
        classes that found nothing.
        """
        if not (200 <= status < 400) or _has_waf_evidence(headers):
            return
        for marker in _body_block_signatures(body) - self._benign_markers:
            self._benign_markers.add(marker)
            self._logger.info(
                "Block signature %r served in an unblocked %d response — "
                "recorded as this target's own vocabulary, not evidence of blocking",
                marker,
                status,
            )

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    @property
    def first_request_at(self) -> datetime | None:
        """When the first request was authorized, or ``None`` if none was."""
        return self._first_request_at

    @property
    def last_request_at(self) -> datetime | None:
        """When the most recent request was authorized, or ``None``."""
        return self._last_request_at

    def _stamp_request_window(self) -> None:
        """Extend the request window to now.

        Called on the authorized path only: a refused request is not a request
        the engagement made, and a window that counted refusals would report
        testing that never happened.
        """
        now = datetime.now(UTC)
        if self._first_request_at is None:
            self._first_request_at = now
        self._last_request_at = now

    def stats(self) -> dict[str, object]:
        """Runtime counters for the report and the run summary."""
        profile = get_active_benchmark_profile()
        return {
            "requests_authorized": self._requests_authorized,
            # The window is stated even when it is empty, because its ABSENCE is
            # what tells a renderer that a bundle predates this stamp — the one
            # case in which a degenerate testing window is a missing record
            # rather than a lie.
            "first_request_at": (
                self._first_request_at.isoformat() if self._first_request_at else None
            ),
            "last_request_at": (
                self._last_request_at.isoformat() if self._last_request_at else None
            ),
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
            # Named, not just counted: a marker discarded as this target's own
            # vocabulary is a halt that did not happen, and an operator reading
            # a run that kept going past a WAF-shaped page deserves to see
            # which phrase was ruled out and why.
            "benign_block_markers": sorted(self._benign_markers),
            # The boundary those discards draw, beside the discards themselves.
            # An operator reading "we ruled out 'access denied'" is entitled to
            # the sentence saying what that rules out along with it, in the same
            # record rather than in a source comment they will not read.
            "blocking_body_arm_boundary": BLOCKING_BODY_ARM_BOUNDARY,
            # Per-account, because a total is not evidence about its parts: 24
            # attempts spread over six accounts and 24 against one are the same
            # number and a different engagement.
            "max_credential_attempts_per_account": (
                self.policy.max_credential_attempts_per_account
            ),
            # Stated apart from the total, because they are two different
            # allowances and a run where the deterministic pass hit ITS bound is
            # not a run that exhausted the account.
            "adaptive_auth_credential_reserve": self._reserve(),
            "credential_attempts": {
                f"{account} @ {origin}": count
                for (origin, account), count in sorted(self._credential_attempts.items())
            },
            "credential_stops": {
                f"{account} @ {origin}": f"{signal.kind.value}: {signal.marker}"
                for (origin, account), signal in sorted(self._credential_stops.items())
                if signal.kind is not None
            },
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


def _origin(url: str) -> str:
    """``scheme://netloc`` of *url*, or the url itself when it has no origin.

    The fallback is deliberate: a relative or malformed URL still has to key a
    counter, and grouping every unparseable one together bounds them jointly
    rather than handing each a fresh budget of its own.
    """
    parsed = urlparse(url or "")
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return url or ""


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


def _has_waf_evidence(headers: dict[str, str]) -> bool:
    """Whether *headers* independently name an edge/WAF vendor.

    Read twice, for opposite purposes: it promotes a soft status to a block,
    and it disqualifies a response from ever serving as a benign-marker
    control. A WAF that soft-blocks with a 200 is exactly the response that
    must not teach us its own block page is the app's normal vocabulary.
    """
    lower = {k.lower(): (v or "").lower() for k, v in headers.items()}
    return any(h in lower for h in _WAF_HEADERS) or "cloudflare" in lower.get("server", "")


def _body_block_signatures(body: str) -> frozenset[str]:
    """Block-page signatures present in *body*.

    Returns the matched signatures rather than a boolean so both consumers can
    name what matched: the halt path needs to know which marker fired, and the
    control path needs to know which marker to discard.
    """
    lower_body = body[:4096].lower() if body else ""
    if not lower_body:
        return frozenset()
    return frozenset(sig for sig in _BLOCK_BODY_SIGNATURES if sig in lower_body)


#: What the body arm of :func:`_looks_blocked` CANNOT see, now that it takes a
#: control — stated as a boundary rather than left as a footnote in the commit
#: that introduced it.
#:
#: The control discards a block signature this target already served in a
#: response that was not blocked. That is right, and it costs exactly one case:
#: **a target that genuinely blocks with a phrase it also ships
#: unconditionally.** An SPA whose error shell carries "access denied" on every
#: route, and which then really does start refusing us with that same shell, is
#: invisible to the body arm — the marker was learned as benign before the block
#: began and it stays learned.
#:
#: The case is accepted rather than mitigated, and the reason is which direction
#: each error runs in:
#:
#: * **What the control prevents** is a FALSE halt. A halt is an
#:   absence-generating event — every class downstream of it registers NEVER
#:   INVOKED, and a report assembled from those rows reads as an engine that
#:   looked and found nothing. On cal.diy that cost 29 classes and the
#:   deliverable said nothing about why.
#: * **What the control costs** is a LATE halt on this one shape. Late, not
#:   absent: the status arm is unaffected and outranks every keyword, so a 429
#:   or a 503 halts regardless, and a WAF header halts regardless. The body arm
#:   is the weakest of the three and it is the only one narrowed.
#:
#: A run that keeps going against a target refusing it with 200s is a run that
#: wasted requests; a run that stops against a target serving it normally is a
#: run that reported an empty application as a clean one. Those are not
#: symmetric, and the boundary is drawn on the asymmetry.
#:
#: Named here, asserted by ``test_the_blocking_body_arm_declares_what_it_lost``,
#: and quoted in the governor summary's own vocabulary so an operator reading
#: ``benign_block_markers`` can find the reason a phrase was ruled out.
BLOCKING_BODY_ARM_BOUNDARY = (
    "the body arm cannot see a block whose signature this target also ships in "
    "responses that are not blocked — that marker is learned as this "
    "application's own vocabulary and stays learned. The status arm (429/503) "
    "and the WAF-header arm are unaffected and outrank every keyword, so such a "
    "block is detected LATE rather than never. The alternative is an "
    "unconditionally-shipped marker halting a run that was never blocked, which "
    "generates absences that read as a clean target"
)


def _looks_blocked(
    status: int,
    headers: dict[str, str],
    body: str,
    benign_markers: frozenset[str] = frozenset(),
) -> bool:
    """Whether a response reads as "the target is blocking us".

    **The body arm takes a control, and it costs no traffic.** A marker this
    same target already served in a response that was NOT blocked is the
    application's own error vocabulary, not evidence about this response —
    the same rule ``_login_verdict`` and ``classify_lockout`` take, sourced
    from a response the engagement already holds rather than from a request a
    rail dispatched on its own behalf. Consecutive-blocked was the mitigation
    of record and it does not bound an unconditionally-shipped marker: an SPA
    that ships its error strings in every shell satisfies "consecutive" by
    construction and the counter never resets.

    Ordering is part of the rule, and it is invariant 98's: **a status outranks
    a keyword.** A 429 or 503 is a block whatever the body says and whatever
    the control holds, because the target declared it.

    **What this cannot see is declared**, in
    :data:`BLOCKING_BODY_ARM_BOUNDARY`: a target that genuinely blocks with a
    phrase it also ships unconditionally is invisible to the body arm, and is
    caught late by the status and header arms rather than never. Written down
    because a control that narrows an oracle has a cost, and a cost nobody
    stated is a cost the next reader will rediscover as a bug.

    Args:
        status: HTTP status code.
        headers: Response headers.
        body: Response body.
        benign_markers: Signatures already observed in an unblocked response
            from this target. Matches against these are discarded.

    Returns:
        ``True`` when the response is evidence the target is refusing us.
    """
    if status in _HARD_BLOCK_STATUSES:
        return True

    # The marker comparison stays HERE, in the function that returns the
    # verdict, rather than behind the helper the learning path calls. The
    # marker-oracle guard computes its domain from the code that decides, and
    # a read hoisted into a helper it does not classify as verdict-shaped is a
    # marker oracle that quietly leaves the guard's sight.
    lower_body = body[:4096].lower() if body else ""
    if any(sig in lower_body for sig in _BLOCK_BODY_SIGNATURES if sig not in benign_markers):
        return True

    if status in _SOFT_BLOCK_STATUSES and _has_waf_evidence(headers):
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
    "BLOCKING_BODY_ARM_BOUNDARY",
    "get_active_governor",
    "set_active_governor",
]
