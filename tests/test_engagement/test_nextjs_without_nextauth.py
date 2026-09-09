"""The honesty control: a Next.js application that does NOT use NextAuth.

cal.diy is the target the adaptive layer was built for, and the agent reaches its
credential destination from three observations: the framework fingerprint
(`X-Powered-By: Next.js` plus a `Vary` negotiating React Server Components), a
`<form>` declaring no action, and a `csrfToken` hidden field with no cookie of
that shape.

**Two of those three are present on every Next.js deployment there is.** Only the
third is NextAuth's signature. So a layer that proposes `/api/auth/callback/
credentials` from the fingerprint alone has recognised a framework rather than
reasoned from evidence, and it will do that on every client Next.js application —
which is a wrong confident credential POST, not a coverage gap.

umami is the control (`docker/docker-compose.yml::umami`). Real Next.js App
Router, real product, and its credential exchange is `POST /api/auth/login` with
a JSON body returning a bearer token; `/api/auth/csrf`, `/api/auth/providers`,
`/api/auth/session` and `/api/auth/callback/credentials` all answer 404.

What is pinned HERE is the half that must hold with no model in the room: **the
engine's own reading has to make the two shapes distinguishable.** If the
briefing flattened them — if a reader of the observation could not tell umami
from cal.diy — then no amount of reasoning could get this right and a correct
answer would be luck. The live half is
`scripts/live_adaptive_auth_validation.py` against the compose service, recorded
in `docs/methodology/adaptive-authentication.md`.

The bytes are the target's own, recorded from the running container
(`tests/fixtures/auth/umami_login_curl.txt`), and the reading is done by the
engine's own functions, imported rather than restated.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.engagement.auth_agent import AuthObservation
from clinkz.tools.auth import (
    _csrf_fields_without_cookie,
    _form_field_names,
    _FormFieldParser,
    _framework_fingerprint,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "auth"

#: The exact fingerprint both applications produce. Recorded from cal.diy on
#: 2026-09-09 and asserted below to be what umami's own headers produce too —
#: which is the whole premise of the control.
SHARED_NEXTJS_FINGERPRINT = (
    "X-Powered-By: Next.js; Vary negotiates React Server Components (rsc, next-router-state-tree)"
)


def _exchange() -> tuple[dict[str, str], str]:
    """The recorded ``GET /login``, split into headers and body.

    One curl dump, the same shape the Meridian fixtures beside it use: the
    status line, the response headers, a blank line, and the bytes the container
    served. Split on the FIRST blank line, because the body is HTML and has
    several of its own.
    """
    raw = (FIXTURES / "umami_login_curl.txt").read_text(encoding="utf-8")
    separator = "\r\n\r\n" if "\r\n\r\n" in raw else "\n\n"
    head, _, body = raw.partition(separator)
    headers: dict[str, str] = {}
    for line in head.splitlines():
        if ":" not in line or line.startswith("HTTP/"):
            continue
        name, _, value = line.partition(":")
        headers[name.strip()] = value.strip()
    return headers, body


def _page() -> str:
    return _exchange()[1]


def _headers() -> dict[str, str]:
    return _exchange()[0]


def _login_fields():
    parser = _FormFieldParser()
    parser.feed(_page())
    return parser.login_form


# ---------------------------------------------------------------------------
# The two facts that are the SAME
# ---------------------------------------------------------------------------


def test_the_framework_fingerprint_is_the_one_cal_diy_produces() -> None:
    """Fact one: the headers say Next.js, in exactly the same words.

    If this ever stops matching, the control has stopped being a control — the
    premise is that the fingerprint cannot discriminate.
    """
    fingerprint = _framework_fingerprint(_headers())
    assert "Next.js" in fingerprint
    assert "rsc" in fingerprint.lower()
    assert fingerprint == SHARED_NEXTJS_FINGERPRINT, (
        "umami and cal.diy must produce the SAME fingerprint for this target to "
        f"control for anything. umami produced {fingerprint!r}"
    )


def test_the_login_page_names_no_destination_either() -> None:
    """Fact two: nothing on the page says where the credential goes.

    umami serves no ``<form>`` at all, which is the stronger form of cal.diy's
    "a form declaring no action" — and the engine records them as two different
    diagnoses rather than one.
    """
    form = _login_fields()
    assert not form.from_form, "the fixture is supposed to carry no <form> element"
    assert not form.form_action, "a page with no form cannot have declared an action"


# ---------------------------------------------------------------------------
# The fact that is DIFFERENT, and it is the only one that decides
# ---------------------------------------------------------------------------


def test_no_csrf_shaped_field_without_a_cookie() -> None:
    """The NextAuth signature is ABSENT, and the engine reports its absence.

    cal.diy's ``csrfToken`` field arriving with no cookie of that shape is the
    observation that makes NextAuth's ``/api/auth/csrf`` the right hypothesis:
    the page expects a token a call the deterministic pass never made would have
    minted. umami has no such field, so the same hypothesis is unsupported here.
    """
    form = _login_fields()
    assert _csrf_fields_without_cookie(form.hidden_fields, {}) == [], (
        "umami must NOT present a csrf-shaped hidden field — that field is the "
        "one input distinguishing a NextAuth deployment from any other Next.js "
        "one, and a fixture carrying it would make this control vacuous"
    )


def test_the_page_ships_no_nextauth_route_for_the_engine_to_read_back() -> None:
    """Nothing in the bytes names the answer, in either direction.

    A control where the target itself spells out its credential route would test
    the reader, not the reasoner.
    """
    page = _page().lower()
    for spelling in ("/api/auth/csrf", "/api/auth/callback", "/api/auth/providers", "nextauth"):
        assert spelling not in page, f"the fixture leaks {spelling!r}"


# ---------------------------------------------------------------------------
# The briefing has to carry the difference through
# ---------------------------------------------------------------------------


def _umami_observation() -> AuthObservation:
    form = _login_fields()
    return AuthObservation(
        base_url="http://umami:3000",
        login_url="http://umami:3000/login",
        posted_to="http://umami:3000/login",
        post_status=200,
        page_declared_a_form=form.from_form,
        form_action_declared=bool(form.form_action),
        form_field_names=_form_field_names(form),
        csrf_fields_without_cookie=_csrf_fields_without_cookie(form.hidden_fields, {}),
        login_page_cookie_names=[],
        framework_fingerprint=_framework_fingerprint(_headers()),
        login_page_content_type="text/html",
        post_changed_nothing=True,
    )


def _cal_diy_observation() -> AuthObservation:
    """The cal.diy shape, from the values engagement e4814440 actually recorded."""
    return AuthObservation(
        base_url="http://cal:3000",
        login_url="http://cal:3000/login",
        posted_to="http://cal:3000/login",
        post_status=200,
        page_declared_a_form=True,
        form_action_declared=False,
        form_field_names=["csrfToken", "email", "password"],
        csrf_fields_without_cookie=["csrfToken"],
        login_page_cookie_names=[],
        framework_fingerprint=SHARED_NEXTJS_FINGERPRINT,
        login_page_content_type="text/html",
        post_changed_nothing=True,
    )


def test_the_two_briefings_are_not_the_same_briefing() -> None:
    """The load-bearing assertion.

    Both applications are Next.js, both served a login page naming no
    destination, and both answered the credential POST with an unchanged body.
    If the briefing rendered those two identically, the layer would be choosing
    between them on the framework name alone and a correct answer on either
    would be luck.
    """
    assert _umami_observation().as_briefing() != _cal_diy_observation().as_briefing()


def test_the_difference_is_the_csrf_observation() -> None:
    """And it is the RIGHT difference — not an incidental one like a hostname."""
    umami = _umami_observation()
    cal = _cal_diy_observation()

    assert umami.framework_fingerprint == cal.framework_fingerprint
    assert umami.post_changed_nothing == cal.post_changed_nothing
    assert umami.csrf_fields_without_cookie == []
    assert cal.csrf_fields_without_cookie == ["csrfToken"]

    briefing = umami.as_briefing()
    assert "csrfToken" not in briefing, (
        "the umami briefing must not mention a CSRF field it never observed"
    )
    assert "Next.js" in briefing, "the fingerprint is still the load-bearing fact it has"


NEXTAUTH_SPELLINGS = ["/api/auth/csrf", "/api/auth/callback/credentials", "nextauth"]


@pytest.mark.parametrize("spelling", NEXTAUTH_SPELLINGS)
def test_the_briefing_never_names_the_answer(spelling: str) -> None:
    """Neither briefing may contain a route. The engine states facts, not routes."""
    for observation in (_umami_observation(), _cal_diy_observation()):
        assert spelling not in observation.as_briefing().lower()
