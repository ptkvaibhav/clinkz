# Authentication shapes — observing the login, never guessing its name

> Invariants 87–88 in [`CLAUDE.md`](../../CLAUDE.md). The rules are there; the
> incident is here.

## The target that found it

DVWA is form + cookie. Juice Shop is JSON + bearer. The authenticator
(`tools/auth.py`) and the authenticated-state assertion
(`engagement/auth_state.py`) were both built against exactly those two, so every
defect below was invisible: each one needed a target that combined the pieces
differently.

**Meridian Portal** (`docker/meridian/app.py`) is that third shape. It is not
intentionally vulnerable — it exercises the *authentication path*, nothing else:

| Property | Value | What it defeats |
|---|---|---|
| Login page | `/portal/gateway` | Every list of login path names |
| Login API | `POST /portal/v3/session-open`, reached only via the form's `action` | Six canned API routes |
| Identity field | `account` | `email` / `username` auto-detection |
| Session | `Set-Cookie` on a **JSON** response, no token anywhere | A token-only extractor |
| Anonymous denial | **302 to the login page**, not 401/403 | A status-class oracle |
| One protected route | `/settings` answers **200 with the login page** | An SPA shell in disguise |
| Two public routes | `/` and `/pricing`, byte-identical either way | A discriminator that fires on everything |

Its vocabulary is controlled on purpose: no page outside the authenticated area
contains "welcome", "dashboard", "logout" or "sign out", because those are the
literal strings the old success heuristic and the session-marker discriminator
match on, and a target that hands them out for free makes every result here
ambiguous.

`MERIDIAN_LOGIN_PATH` is an environment variable rather than a constant because
of one question: does an oracle read the **shape** of a redirect or the
**spelling** of its destination? Running the same application at
`/portal/gateway` and at `/login` answers it in one step, and a constant could
not.

## Defect 1 — a 415 was a proven session

`_check_login_success` returned `True` on **status 415**.

The path: Meridian's login page is a real HTML form whose `action` is a JSON-only
API. The form arm posted it form-encoded to `/portal/v3/session-open`, the server
answered `415 Unsupported Media Type`, and the heuristic reached

```python
if login_path and final_path and final_path != login_path:
    return True          # "redirected away from login → success"
```

`final_url` was the form's action and `login_url` was the login page. They differ.
**No redirect had occurred at all** — the redirect chain was empty — and the
server had just stated in the clearest terms available to it that it accepted
nothing.

Three things were wrong and each is fixed separately:

1. **A 4xx is never success.** `status_code >= 400` returns `False` before any
   other test runs.
2. **A different final path is not a redirect.** The redirect test now reads
   `redirect_chain`, which is empty unless a redirect genuinely happened.
3. **Success requires positive evidence** — session material (a cookie the
   exchange set, or a token in the body) or a real redirect away from the login
   page, or an authenticated-page marker on a 2xx. The absence of a failure
   keyword is not evidence of anything.

### The 415 is not merely refused — it is used

A 415 is the one status that carries a machine-readable instruction: the server
read the request, understood it, and refused it *for a reason it named*.
`_negotiated_content_type` reads that reason from three channels, protocol first
— `Accept-Post`, `Accept`, then the JSON shapes an API uses to say the same
thing (`{"expects": {"content_type": ...}}`) — and the credentials are re-POSTed
to the same action under that type.

**Prose is never parsed.** A body saying "please send application/json" states
nothing machine-readable, and a guard that reads text the target controls is a
suppression primitive handed to the target (invariant 55). A 415 naming a type
we cannot encode is reported, not guessed at.

The field names come from the form's own HTML and the encoding from the server's
own answer. Neither half of the successful request is a guess — which is the
only reason this retry is allowed to exist.

### A success that carries no session is a contradiction

The old code produced `success=True, session_cookies={}, bearer_token=""` and
handed it on. `assert_authenticated` then failed with *"no session material was
supplied"* — an accurate message about the wrong component, three layers from the
code that invented the success.

`_require_session_material` catches it at the seam where the claim is made.

## Defect 2 — the redirect discriminator read a name

```python
_LOGIN_HINTS = ("login", "signin", "sign-in", "sign_in", "auth", "sso", "session/new")
if anon.redirects_to_login and not authed.redirects_to_login:
```

Seven substrings stood between the engine and **the commonest denial shape in
production web applications**. `/portal/gateway?next=%2Fapi%2Forders` contains
none of them.

The decisive test: rename the page to `/login`, change nothing else, and the
verdict flips. That is a name oracle, and invariant 64 already says the alias is
OBSERVED, never inferred.

**The gate is now the redirect.** An anonymous 3xx and an authenticated 2xx on
the same URL is the boundary — the two requests differ in exactly one thing, and
that thing is the session. Where the redirect points is corroboration, gathered
and reported but never required:

* the destination is spelled like a login surface (the old list, demoted);
* the destination **serves a password input** — one extra request, made once,
  after the boundary is already established;
* the `Location` carries a query parameter whose **value** names the path we
  requested. An application that says "go here, and afterwards come back to the
  thing you wanted" is describing a login redirect by construction. The
  parameter's own name is not consulted: `next`, `return_to`, `r` and `ReturnUrl`
  are the same idea, and matching on the value reads the application instead of
  a list we would have to maintain.

`follow_redirects=False` on both arms of the comparison is what makes any of this
observable, and it stays.

### `looks_unauthenticated` deliberately did NOT change

The mid-run session sentinel still keys on `redirects_to_login`. It is a
heuristic that raises a flag for an oracle to check — never a verdict — and
firing it on *any* 3xx would flood it with the ordinary redirects a scan walks
through all day. A permanent false alarm trains an operator to skim the section
where a real one will appear (invariant 77).

## Defect 3 — the same name filter, one layer up

`_find_login_url` collected URLs from recon, the crawl, the summaries and the
state store, then discarded every one that did not match six path names. So
Meridian could link its login page from its own landing page, have the crawler
find it, hand it to this method — and still come back "no login surface proven".

The strategies now **collect** candidates and a single shape test decides.
Login-shaped names are tried **first**, because each shape test costs a request;
being login-shaped is no longer what makes a candidate *eligible*, only what
makes it *early*. `LOGIN_SHAPE_PROBE_BUDGET` bounds the walk and announces itself
when it bites, because a bound that decides coverage is never silent
(invariant 14).

Recon's explicit `login_urls` dict is still taken as given: it is a producer's
declaration, and the one entry that does not need confirming.

## Defect 4 — one message for three different failures

The abort message said, unconditionally:

```
  - the application has no URL that behaves differently when authenticated
    among the ones tried; supply a known authenticated-only URL
```

On the run that produced it, `attempted` was empty. **The assertion never ran**,
and the credentials had never been offered to the application at all. All three
of the message's remedies were wrong at once, and an operator acting on the third
would have gone looking for a protected URL to declare for a session that failed
three steps earlier.

**An error may not assert a negative about a comparison that was never made.**
The per-role line now reports which of three things happened:

| What happened | What the message says |
|---|---|
| Nothing was dispatched | No credential was ever offered; which step ended it; the URL we would have used |
| A credential POST was dispatched and refused | The URL it **actually went to** — not the login URL, whenever a form `action` pointed elsewhere — and why |
| The assertion ran and found nothing | That it ran, plus every URL compared with **both** status codes |

The remedies are filtered the same way. `assert_url` is only offered to a run
that reached the assertion; the three discovery declarations are only offered to
one that did not.

`AuthResult.posted_to` is what makes the middle row sayable: "login failed at
`/portal/gateway`" and "we POSTed to `/portal/v3/session-open` and it returned
401" are different facts, and an operator cannot tell them apart from the first.

## Defect 5 — declarability

`assert_url` exists, is documented and is gate-loaded. Three things were not
declarable at all, and the worst of them was already known to the operator:

`_try_api_login` took the declared `login_url`, kept only its **origin**, and
iterated six canned routes. The operator had told us where their login lives and
we ignored it. **A declaration that is discarded is worse than no declaration,
because the operator believes the engine knows.**

Three new fields on `RoleCredential`, all of which **OVERRIDE discovery rather
than seed it**:

| Field | For |
|---|---|
| `login_api_url` | The JSON login route, when it is not the login *page* |
| `login_field` | The identity field name, when it is neither `email` nor `username` |
| `login_content_type` | The credential POST's encoding, overriding both the form's `enctype` and any negotiation |

`login_content_type` is validated against `ENCODABLE_CONTENT_TYPES` at model
construction: declaring a type the authenticator cannot produce would be silently
ignored, which is the failure the field exists to end. `extra="forbid"` already
catches a misspelled key; this catches a misspelled value.

## Defect 6 — the arms ran in a fixed order

The form arm ran unconditionally and the JSON arm only saw what it left behind.
`_encoding_order` now decides from what was observed, strongest first:

1. the operator declared a content type;
2. the login URL serves `application/json` — it is an API, not a page;
3. the form declares an `enctype`.

With none of them the answer is **form-first**, which is unchanged behaviour for
every target that worked before — and it is the arm that can read a form
`action`, which is the only way a JSON login route at an unguessable path is ever
discovered. Meridian is found by the form arm and authenticated by the
negotiation, not by the ordering.

## The regression that is the test

`tests/test_engagement/test_meridian_auth.py` runs Meridian in a thread on an
ephemeral port (standard library only — no container, no network beyond
loopback) and asserts that **`/portal/gateway` and `/login` reach the same
verdict**.

The equality is on `(established, discriminator, authenticated_status,
anonymous_status)`, not on `established` alone. That matters, and the old code
proves why: under the name gate, `/portal/gateway` still reached
`established=True` — by `session_marker`, a body keyword — while `/login` proved
it by the actual boundary. An equality assertion on `established` would have
passed. A name oracle passes every test that only ever spells the login page the
way it expects.

Both execution modes are covered. `tests/test_tools/test_auth_curl_path.py`
parses fixtures captured from a real `curl -s -S -D - -X POST -L` against a
running Meridian — the bytes curl writes, not a plausible transcript of them
(invariant 83) — because an application that authenticates under
`TOOL_EXEC_MODE=local` and not under `docker` is a defect the mode hides rather
than a property of the application.

## Running Meridian

```bash
docker compose -f docker/docker-compose.yml up -d meridian          # :8090
MERIDIAN_LOGIN_PATH=/login docker compose -f docker/docker-compose.yml \
    up -d --force-recreate meridian                                 # the other spelling
```

Accounts: `acct-4417` / `s3cure-passphrase` (privilege 0) and `acct-9002` /
`winter-harbor-77` (privilege 10) — two genuinely different principals, so a
multi-role engagement against it has an uphill crossing to declare.
