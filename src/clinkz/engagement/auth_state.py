"""Authenticated scanning — detect the mechanism, PROVE the session, keep it.

Scanning an authenticated application anonymously is the worst failure this tool
has: it produces an empty report and a client hears "we found nothing". Nothing
in the run looks wrong. Every phase reports success. The engagement simply never
saw the application.

So authentication here is not "we called login and it returned 200". It is an
**assertion with a control**, built the same way every confirmation oracle in
this codebase is built:

  * Issue the SAME request twice — once carrying the session material, once
    deliberately clean.
  * Require a **deterministic difference** that only an authorization boundary
    produces: a different status class, a login redirect present anonymously and
    absent authenticated, or a session marker present only when authenticated.
  * A body-length delta proves nothing and is explicitly NOT accepted. Page
    chrome, a CSRF token, a timestamp — all of those move the length without any
    boundary existing.

If no discriminator is found, :func:`assert_authenticated` reports
``established=False`` with the comparison it made, and the caller aborts the
engagement loudly. "We could not prove the session is authenticated" is an
honest, actionable outcome. Scanning anyway is not.

The module takes an injected :class:`HttpProbe` rather than importing the HTTP
tool directly, so the logic is exercisable without a network and the orchestrator
supplies the real, scope-enforcing, governed client.
"""

from __future__ import annotations

import logging
import re
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

#: Location/body hints that a response is the login page rather than content.
_LOGIN_HINTS = ("login", "signin", "sign-in", "sign_in", "auth", "sso", "session/new")

#: Markers that appear once a session exists. Presence ONLY in the authenticated
#: response is the discriminator — presence in both proves nothing.
_SESSION_MARKERS = ("logout", "log out", "sign out", "signout", "my account", "log off")

#: Routes probed when looking for a JSON/API login endpoint. Same list the
#: WebAuthenticator uses, kept in step deliberately: detection and execution must
#: agree about what an API login looks like.
_API_LOGIN_ROUTES: tuple[str, ...] = (
    "/rest/user/login",
    "/api/login",
    "/api/auth/login",
    "/api/v1/auth/login",
    "/auth/login",
    "/login",
)

#: Paths probed when looking for an HTML login form.
_FORM_LOGIN_PATHS: tuple[str, ...] = (
    "/login.php",
    "/login",
    "/signin",
    "/users/sign_in",
    "/admin",
    "/auth",
    "/wp-login.php",
    "/account/login",
)

_PASSWORD_INPUT_RE = re.compile(r"""<input[^>]+type\s*=\s*['"]?password['"]?""", re.IGNORECASE)

#: Conventional paths that are authorization-protected in most applications,
#: tried when the operator has not named one. These are naming CONVENTIONS, not
#: target literals: REST collection nouns, the "who am I" route, and the usual
#: account areas. Both lower-case and PascalCase collection spellings appear
#: because ORM-generated APIs (Sequelize, LoopBack) expose the model name
#: verbatim, and paths are case-sensitive.
#:
#: This list is a convenience, not the mechanism. An application whose protected
#: surface is named something else supplies it via ``assert_url`` on the role —
#: which is why :func:`assert_authenticated` reports what it tried when nothing
#: discriminates, rather than guessing further.
PROTECTED_PATH_CANDIDATES: tuple[str, ...] = (
    "/api/users",
    "/api/Users",
    "/api/user",
    "/api/me",
    "/api/account",
    "/api/profile",
    "/api/orders",
    "/api/Orders",
    "/api/basket",
    "/api/BasketItems",
    "/rest/user/whoami",
    "/rest/basket/1",
    "/me",
    "/profile",
    "/account",
    "/settings",
    "/dashboard",
    "/admin",
    "/orders",
)


class AuthStateError(Exception):
    """Raised when an authenticated session could not be established or proven."""


class AuthMechanism(StrEnum):
    """How the application authenticates.

    Attributes:
        NONE: No authentication surface was found; the app appears open.
        FORM: HTML login form; the session rides in a cookie.
        BEARER: JSON login route returning a token used as ``Authorization``.
        COOKIE: A session cookie is issued without a discoverable HTML form.
        UNKNOWN: An auth surface exists but its shape could not be determined.
    """

    NONE = "none"
    FORM = "form"
    BEARER = "bearer"
    COOKIE = "cookie"
    UNKNOWN = "unknown"


class ProbeResponse(BaseModel):
    """A minimal HTTP response, as the assertion needs to see it.

    Attributes:
        status: HTTP status code; ``0`` when the request failed outright.
        headers: Response headers.
        body: Response body.
        error: Transport error, when the request never completed.
    """

    status: int = 0
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    error: str = ""

    @property
    def location(self) -> str:
        """The ``Location`` header, case-insensitively."""
        for key, value in self.headers.items():
            if key.lower() == "location":
                return value
        return ""

    @property
    def redirects_to_login(self) -> bool:
        """Whether this response redirects to something login-shaped."""
        if self.status not in (301, 302, 303, 307, 308):
            return False
        target = self.location.lower()
        return any(hint in target for hint in _LOGIN_HINTS)

    @property
    def serves_login_form(self) -> bool:
        """Whether the body is an HTML login form."""
        return bool(_PASSWORD_INPUT_RE.search(self.body or ""))


class HttpProbe(Protocol):
    """The HTTP capability this module needs.

    The orchestrator supplies an adapter over the engagement's real HTTP client,
    so scope enforcement, the governor, and the docker/host routing all still
    apply. Tests supply a fake.
    """

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        follow_redirects: bool = False,
    ) -> ProbeResponse:
        """Issue a GET."""
        ...

    async def post_json(self, url: str, payload: dict[str, str]) -> ProbeResponse:
        """Issue a JSON POST."""
        ...


class AuthDetection(BaseModel):
    """What the auth-mechanism probe found.

    Attributes:
        mechanism: The detected mechanism.
        login_url: Where to authenticate.
        evidence: Deterministic observations that led to the conclusion.
        probed: Every URL that was probed, so a wrong answer is diagnosable.
    """

    mechanism: AuthMechanism = AuthMechanism.UNKNOWN
    login_url: str = ""
    evidence: list[str] = Field(default_factory=list)
    probed: list[str] = Field(default_factory=list)


class AuthAssertion(BaseModel):
    """The proof (or the absence of proof) that a session is authenticated.

    Attributes:
        established: Whether authenticated state was PROVEN, not assumed.
        url: The URL the comparison was made against.
        discriminator: Which deterministic difference established it.
        authenticated_status: Status seen with the session material.
        anonymous_status: Status seen deliberately without it.
        evidence: Raw, human-readable observations backing the verdict.
        attempted: Every URL tried, with the outcome, so a failure is diagnosable.
        why_unproven: Why no discriminator was found, when none was.
    """

    established: bool = False
    url: str = ""
    discriminator: str = ""
    authenticated_status: int = 0
    anonymous_status: int = 0
    evidence: list[str] = Field(default_factory=list)
    attempted: list[str] = Field(default_factory=list)
    why_unproven: str = ""


# ---------------------------------------------------------------------------
# Mechanism detection
# ---------------------------------------------------------------------------


async def detect_auth_mechanism(
    probe: HttpProbe,
    base_url: str,
    *,
    extra_login_urls: list[str] | None = None,
) -> AuthDetection:
    """Determine HOW the application authenticates, rather than assuming.

    Probes, in order:

      1. Candidate HTML login paths — a ``type="password"`` input is the
         deterministic form signal.
      2. Candidate JSON login routes — a route that answers a credential-shaped
         POST with 4xx (rather than 404/405) is an API login endpoint that
         exists and rejected our empty credentials, which is exactly what an
         unauthenticated probe should see.
      3. The base URL's ``Set-Cookie`` — a session cookie issued with no
         discoverable form means cookie auth by some other route.

    Nothing here submits real credentials; detection is read-only.

    Args:
        probe: HTTP capability.
        base_url: Application base URL.
        extra_login_urls: Login URLs discovered elsewhere (recon/crawl), tried
            ahead of the generic candidates.

    Returns:
        An :class:`AuthDetection`.
    """
    root = base_url.rstrip("/")
    evidence: list[str] = []
    probed: list[str] = []

    # 1. HTML login form.
    form_candidates = [*(extra_login_urls or []), *(f"{root}{p}" for p in _FORM_LOGIN_PATHS)]
    for candidate in _dedupe(form_candidates):
        resp = await probe.get(candidate, follow_redirects=True)
        probed.append(candidate)
        if resp.status and resp.status < 400 and resp.serves_login_form:
            evidence.append(
                f'GET {candidate} -> {resp.status} with an <input type="password"> '
                "— HTML login form"
            )
            return AuthDetection(
                mechanism=AuthMechanism.FORM,
                login_url=candidate,
                evidence=evidence,
                probed=probed,
            )

    # 2. JSON/API login route.
    for route in _API_LOGIN_ROUTES:
        url = f"{root}{route}"
        resp = await probe.post_json(url, {"email": "", "password": ""})
        probed.append(url)
        if resp.status in (400, 401, 403, 422):
            evidence.append(
                f"POST {url} with empty credentials -> {resp.status} "
                "— an API login route that exists and rejected them"
            )
            return AuthDetection(
                mechanism=AuthMechanism.BEARER,
                login_url=url,
                evidence=evidence,
                probed=probed,
            )

    # 3. Session cookie without a discoverable form.
    root_resp = await probe.get(root or "/", follow_redirects=False)
    probed.append(root or "/")
    set_cookie = ""
    for key, value in root_resp.headers.items():
        if key.lower() == "set-cookie":
            set_cookie = value
            break
    if set_cookie:
        cookie_name = set_cookie.split("=", 1)[0].strip()
        evidence.append(f"GET {root} issued a session cookie '{cookie_name}' with no login form")
        return AuthDetection(
            mechanism=AuthMechanism.COOKIE,
            login_url=root,
            evidence=evidence,
            probed=probed,
        )

    if root_resp.redirects_to_login:
        evidence.append(
            f"GET {root} -> {root_resp.status} redirecting to {root_resp.location} "
            "— an auth surface exists but its shape was not determined"
        )
        return AuthDetection(
            mechanism=AuthMechanism.UNKNOWN,
            login_url=root_resp.location,
            evidence=evidence,
            probed=probed,
        )

    evidence.append(f"No login form, API login route, or session cookie found under {root}")
    return AuthDetection(mechanism=AuthMechanism.NONE, evidence=evidence, probed=probed)


# ---------------------------------------------------------------------------
# The assertion
# ---------------------------------------------------------------------------


async def assert_authenticated(
    probe: HttpProbe,
    candidate_urls: list[str],
    *,
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    username: str = "",
) -> AuthAssertion:
    """Prove the session is authenticated by comparing against an anonymous control.

    Each candidate is fetched twice — with the session material and deliberately
    without it — and accepted only on a discriminator that an authorization
    boundary produces:

      1. ``login_redirect`` — anonymous redirects to a login page, authenticated
         does not.
      2. ``status_class`` — anonymous is 401/403 (or any 4xx), authenticated is 2xx.
      3. ``login_form`` — anonymous is served a login form, authenticated is not.
      4. ``session_marker`` — a logout/account marker present only when
         authenticated.
      5. ``identity_echo`` — the authenticated username appears only in the
         authenticated response.

    A body-length delta is deliberately absent from that list: it is a correlate,
    not a boundary, and accepting it would let page chrome pass for a session.

    Args:
        probe: HTTP capability.
        candidate_urls: URLs to try, best first. The first that yields a
            discriminator wins.
        cookies: Session cookies to present.
        headers: Session headers to present (e.g. ``Authorization: Bearer …``).
        username: The identity we authenticated as, for the identity-echo check.

    Returns:
        An :class:`AuthAssertion`. ``established=False`` means the caller must
        abort rather than scan.
    """
    attempted: list[str] = []
    session_cookies = cookies or {}
    session_headers = headers or {}

    if not session_cookies and not session_headers:
        return AuthAssertion(
            established=False,
            why_unproven=(
                "No session material was supplied — there is nothing to assert. "
                "Authentication did not produce cookies or a bearer token."
            ),
        )

    for url in _dedupe(candidate_urls):
        if not url:
            continue
        authed = await probe.get(
            url, headers=session_headers, cookies=session_cookies, follow_redirects=False
        )
        anon = await probe.get(url, follow_redirects=False)
        attempted.append(
            f"{url}: authenticated={authed.status or 'error'} anonymous={anon.status or 'error'}"
        )
        if not authed.status or not anon.status:
            continue

        assertion = _discriminate(url, authed, anon, username)
        if assertion is not None:
            assertion.attempted = attempted
            logger.info(
                "Authenticated state PROVEN at %s via %s (auth=%d anon=%d)",
                url,
                assertion.discriminator,
                assertion.authenticated_status,
                assertion.anonymous_status,
            )
            return assertion

    return AuthAssertion(
        established=False,
        attempted=attempted,
        why_unproven=(
            "No candidate URL behaved differently with and without the session. "
            "Either the session is not actually authenticated, or none of the "
            "URLs tried is protected. Supply a known authenticated-only URL to "
            "assert against."
        ),
    )


def _discriminate(
    url: str,
    authed: ProbeResponse,
    anon: ProbeResponse,
    username: str,
) -> AuthAssertion | None:
    """Return an assertion when a boundary discriminator is present, else ``None``."""

    def built(discriminator: str, evidence: str) -> AuthAssertion:
        return AuthAssertion(
            established=True,
            url=url,
            discriminator=discriminator,
            authenticated_status=authed.status,
            anonymous_status=anon.status,
            evidence=[evidence],
        )

    if anon.redirects_to_login and not authed.redirects_to_login:
        return built(
            "login_redirect",
            f"Anonymous GET {url} -> {anon.status} Location: {anon.location}; "
            f"authenticated GET -> {authed.status} with no login redirect.",
        )

    anon_denied = anon.status in (401, 403)
    authed_ok = 200 <= authed.status < 300
    if anon_denied and authed_ok:
        return built(
            "status_class",
            f"Anonymous GET {url} -> {anon.status}; authenticated GET -> {authed.status}.",
        )

    if anon.serves_login_form and not authed.serves_login_form and authed_ok:
        return built(
            "login_form",
            f"Anonymous GET {url} returned a login form ({anon.status}); "
            f"authenticated GET returned content ({authed.status}) with no login form.",
        )

    authed_body = (authed.body or "").lower()
    anon_body = (anon.body or "").lower()
    for marker in _SESSION_MARKERS:
        if marker in authed_body and marker in anon_body:
            continue
        if marker in authed_body:
            return built(
                "session_marker",
                f"'{marker}' appears in the authenticated response for {url} "
                "and is absent from the anonymous control.",
            )

    if username:
        needle = username.lower()
        if len(needle) >= 3 and needle in authed_body and needle not in anon_body:
            return built(
                "identity_echo",
                f"The authenticated identity appears in the authenticated response "
                f"for {url} and is absent from the anonymous control.",
            )

    return None


# ---------------------------------------------------------------------------
# Session maintenance
# ---------------------------------------------------------------------------


def looks_unauthenticated(status: int, headers: dict[str, str], body: str) -> bool:
    """Whether a mid-run response says the session has been lost.

    Deliberately narrow. A single 403 is the correct answer to an authorization
    probe — the IDOR class produces them on purpose — so 403 alone does NOT
    count. What counts is being sent back to the login surface: a 401, a redirect
    to a login page, or a body that has become a login form.

    Args:
        status: Response status.
        headers: Response headers.
        body: Response body.

    Returns:
        ``True`` when the response indicates the session is gone.
    """
    if status == 401:
        return True
    resp = ProbeResponse(status=status, headers=headers or {}, body=body or "")
    if resp.redirects_to_login:
        return True
    return bool(body) and resp.serves_login_form


class SessionSentinel:
    """Watches responses for session loss and triggers re-authentication.

    Registered as a response observer on the governor, so it sees every response
    the engagement receives without any methodology having to cooperate. That
    matters: half an engagement silently running unauthenticated is the exact
    failure this exists to prevent, and it will not be noticed by the code that
    caused it.

    Re-authentication itself is asynchronous and belongs to the Orchestrator, so
    this class only raises the flag; :attr:`reauth_needed` is polled.

    Args:
        threshold: Consecutive session-loss signals before the flag is raised.
            More than one, because a single protected-resource redirect during
            ordinary probing is not proof the session died.
    """

    def __init__(self, threshold: int = 3) -> None:
        self.threshold = max(1, threshold)
        self._consecutive = 0
        self._reauth_needed = False
        self.losses_detected = 0
        self.reauths_triggered = 0

    @property
    def reauth_needed(self) -> bool:
        """Whether the Orchestrator should re-authenticate now."""
        return self._reauth_needed

    def observe(self, status: int, headers: dict[str, str], body: str) -> None:
        """Feed one response in."""
        if looks_unauthenticated(status, headers, body):
            self._consecutive += 1
            self.losses_detected += 1
            if self._consecutive >= self.threshold and not self._reauth_needed:
                self._reauth_needed = True
                logger.warning(
                    "Session appears lost (%d consecutive unauthenticated responses) "
                    "— re-authentication required",
                    self._consecutive,
                )
        else:
            self._consecutive = 0

    def clear(self) -> None:
        """Reset after a successful re-authentication."""
        self._consecutive = 0
        if self._reauth_needed:
            self.reauths_triggered += 1
        self._reauth_needed = False


def _dedupe(values: list[str]) -> list[str]:
    """Order-preserving de-duplication."""
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


__all__ = [
    "PROTECTED_PATH_CANDIDATES",
    "AuthAssertion",
    "AuthDetection",
    "AuthMechanism",
    "AuthStateError",
    "HttpProbe",
    "ProbeResponse",
    "SessionSentinel",
    "assert_authenticated",
    "detect_auth_mechanism",
    "looks_unauthenticated",
]
