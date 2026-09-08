"""The one lockout vocabulary — what a login refusal that is NOT about the password looks like.

Two components need this answer and they had one copy between them.
:meth:`~clinkz.agents.exploit.ExploitAgent._test_brute_force` owned a
26-phrase tuple, a header read and a stop rule, because grading a login's
brute-force protection *is* reading those signals; the authenticator, which
sends 16-18 credential POSTs per call and up to 64 against one account across a
default-credential sweep, owned nothing. It read every refusal as "the
credentials were wrong" and kept going.

Those are the same observation used for opposite purposes:

* the methodology reads it to decide whether the TARGET is protected;
* the authenticator reads it to decide whether WE must stop.

so the vocabulary is shared and the two verdicts are not. This module holds the
phrases, the header names and one classifier; each consumer keeps its own
decision. That is the split the destructive vocabulary already uses
(:mod:`clinkz.safety.destructive`), for the same reason: a signal list that
exists twice diverges, and the copy that goes stale is the one nobody is
looking at.

**What this module deliberately does NOT decide.** Whether a signal means the
account is locked or merely challenged is a distinction the consumers care about
and this module records rather than resolves: :class:`LockoutKind` names three,
and every one of them is a stop condition for the authenticator. A captcha is
not a lockout — it is a refusal the application made *without evaluating the
credential*, and reading it as "the password was wrong" and sending N-1 more is
the same defect with a different marker on it.

**And it does not decide what a DISCARD means, either.** ``control_body`` makes
a phrase the control already carried fall out of the verdict
(:attr:`LockoutSignal.discarded`), and the two consumers want opposite things
from that, because a wrong stop costs them different amounts:

* ``_test_brute_force`` **stops on a discard too**. Its whole purpose is sending
  failed logins, it is exempt from the per-account budget by declaration
  (invariant 96), and a login page already displaying a lockout notice is the
  case where continuing is worst. A false stop there costs a shorter series,
  disclosed as an `InconclusiveMeasurement` — cheap.
* :class:`~clinkz.safety.governor.EngagementGovernor` **does not**. A stop there
  refuses every later credential for the account, halts the engagement, and
  asserts to the operator that the client account is locked; a page footer
  reading "rate limit" is not grounds for any of that. What bounds it instead is
  ``max_credential_attempts_per_account``, which is spent whether or not any
  phrase ever matches.

The asymmetry is the point: same observation, two verdicts, and the cost of
being wrong is what sets each one.
"""

from __future__ import annotations

from enum import StrEnum
from typing import NamedTuple

__all__ = [
    "LOCKOUT_PHRASES",
    "RATE_LIMIT_HEADERS",
    "LockoutKind",
    "LockoutSignal",
    "NO_LOCKOUT",
    "classify_lockout",
]


class LockoutKind(StrEnum):
    """Why a login response is not an answer about the credential.

    Three kinds, and the authenticator stops on all three. They are kept apart
    because the *disclosure* differs: an operator whose account was locked has a
    different problem from one whose login is behind a captcha, and both are
    different from a shared rate limiter that will clear on its own.
    """

    #: The account (or the source address) has been locked or blocked.
    LOCKOUT = "lockout"
    #: A rate limiter answered — ``429``, ``Retry-After``, ``X-RateLimit-*``.
    RATE_LIMIT = "rate_limit"
    #: A human-verification gate answered. The credential was never evaluated.
    CAPTCHA = "captcha"


class LockoutSignal(NamedTuple):
    """One classification of one login response.

    Attributes:
        kind: Which of the three, or ``None`` when the response carries no
            signal at all.
        marker: The exact observation — the phrase matched, the header name, or
            the status code. Carried verbatim because a stop the operator cannot
            trace to something the target actually said is a stop they will
            override.
        detail: Where the marker was seen, for the failure message.
        discarded: Phrases that DID match the body and were thrown away because
            the control response carries them too. Kept rather than dropped
            because a discard is the interesting event: it is the difference
            between "the target locked this account" and "this page has the
            word *blocked* in its footer", and an operator who sees a run carry
            on past a phrase needs to be able to see why.
    """

    kind: LockoutKind | None
    marker: str
    detail: str
    discarded: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return self.kind is not None


#: The "no signal" answer, so a consumer never has to construct one.
NO_LOCKOUT = LockoutSignal(None, "", "")


#: Phrases that mark a lockout / rate-limit / captcha-challenge response body.
#:
#: Multi-word wherever a single word would collide with ordinary page furniture
#: — DVWA links to its own captcha lesson from the nav bar of every page, so a
#: bare ``"captcha"`` fires on responses that are nothing of the kind. Each
#: entry is matched case-insensitively as a substring.
LOCKOUT_PHRASES: tuple[tuple[str, LockoutKind], ...] = (
    ("account locked", LockoutKind.LOCKOUT),
    ("account is locked", LockoutKind.LOCKOUT),
    ("account has been locked", LockoutKind.LOCKOUT),
    ("account disabled", LockoutKind.LOCKOUT),
    ("account is disabled", LockoutKind.LOCKOUT),
    ("too many attempts", LockoutKind.LOCKOUT),
    ("too many failed", LockoutKind.LOCKOUT),
    ("too many login", LockoutKind.LOCKOUT),
    ("too many requests", LockoutKind.RATE_LIMIT),
    ("rate limit", LockoutKind.RATE_LIMIT),
    ("rate-limit", LockoutKind.RATE_LIMIT),
    ("temporarily locked", LockoutKind.LOCKOUT),
    ("temporarily blocked", LockoutKind.LOCKOUT),
    ("try again later", LockoutKind.RATE_LIMIT),
    ("try again in ", LockoutKind.RATE_LIMIT),
    ("please wait ", LockoutKind.RATE_LIMIT),
    ("you are blocked", LockoutKind.LOCKOUT),
    ("you have been blocked", LockoutKind.LOCKOUT),
    ("ip blocked", LockoutKind.LOCKOUT),
    ("retry after", LockoutKind.RATE_LIMIT),
    ("captcha required", LockoutKind.CAPTCHA),
    ("enter the captcha", LockoutKind.CAPTCHA),
    ("solve the captcha", LockoutKind.CAPTCHA),
    ("invalid captcha", LockoutKind.CAPTCHA),
    ("incorrect captcha", LockoutKind.CAPTCHA),
    ("verify you are human", LockoutKind.CAPTCHA),
    ("prove you are human", LockoutKind.CAPTCHA),
    ("suspicious activity", LockoutKind.LOCKOUT),
)

#: Response headers that are themselves the signal, and what they mean.
RATE_LIMIT_HEADERS: tuple[str, ...] = ("retry-after", "x-ratelimit-remaining", "x-rate-limit")


def classify_lockout(
    status: int,
    headers: dict[str, str] | None,
    body: str,
    control_body: str = "",
) -> LockoutSignal:
    """Classify one login response as a refusal that is not about the credential.

    Order is deliberate. A **header or status** is a protocol artifact the
    application emitted deliberately, and it is read before any body text: it
    cannot be page furniture, and it cannot be attacker-influenced content the
    way a body can. Only then are the phrases consulted.

    **And the phrases are consulted against a CONTROL.** A marker that is
    present in a response the credential never touched is not evidence about
    the credential — invariants 27 and 30, which the exploit path enforces on
    every marker oracle it dispatches and which this function had no equivalent
    of. It matters more here than almost anywhere else in the engine: this
    classifier does not grade a target, it STOPS THE RUN, and it stops it by
    asserting something about the client account. A page whose footer says
    "temporarily blocked", whose help text says "too many attempts", whose nav
    links to a captcha lesson — DVWA does exactly that, which is why every
    phrase below is multi-word — halted the engagement and told the operator
    their account was locked.

    The control is whatever response this caller holds that the credential did
    not produce: the login-page GET for the authenticator, the unauthenticated
    page baseline for ``_test_brute_force``. Absent (``""``), nothing is
    discarded and the behaviour is exactly what it was — a caller with no
    control is not silently given a worse answer, it is given the old one.

    Headers and status are deliberately NOT control-compared. That is the same
    reasoning that puts them first: a ``Retry-After`` is not page furniture, it
    is the server naming a wait, and a control GET that happens to carry one is
    a rate limiter we should also stop for.

    ``429`` counts on its own. ``Retry-After`` counts on its own — a server that
    names a wait is telling us to wait whatever its status code says.
    ``X-RateLimit-Remaining: 0`` counts; a non-zero remaining does not, because
    a budget with room left in it is not a refusal.

    Args:
        status: HTTP status of the response.
        headers: Response headers. Read case-insensitively; ``None`` is treated
            as none present.
        body: Response body.
        control_body: A response the credential did not produce. Any phrase
            found in BOTH is discarded and reported in
            :attr:`LockoutSignal.discarded`.

    Returns:
        A :class:`LockoutSignal`. Falsy (:data:`NO_LOCKOUT`) when the response
        carries no such signal — which is NOT a statement that the target has no
        lockout, only that this response did not show one.
    """
    lower_headers = {k.lower(): (v or "") for k, v in (headers or {}).items()}

    if status == 429:
        return LockoutSignal(LockoutKind.RATE_LIMIT, "429", "HTTP status")

    retry_after = lower_headers.get("retry-after", "").strip()
    if retry_after:
        return LockoutSignal(
            LockoutKind.RATE_LIMIT, f"Retry-After: {retry_after}", "response header"
        )

    remaining = lower_headers.get("x-ratelimit-remaining", "").strip()
    if remaining and remaining.lstrip("+-").isdigit() and int(remaining) <= 0:
        return LockoutSignal(
            LockoutKind.RATE_LIMIT,
            f"X-RateLimit-Remaining: {remaining}",
            "response header",
        )

    low = (body or "").lower()
    control_low = (control_body or "").lower()
    discarded: list[str] = []
    for phrase, kind in LOCKOUT_PHRASES:
        if phrase not in low:
            continue
        if control_low and phrase in control_low:
            discarded.append(phrase)
            continue
        return LockoutSignal(kind, phrase, "response body", tuple(discarded))

    return LockoutSignal(None, "", "", tuple(discarded)) if discarded else NO_LOCKOUT
