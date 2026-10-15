# The SPA + separate-origin IdP shape — cold classification on main

**Fixture:** `docker/spa-keycloak/` (Northwind Notes + Keycloak 26.0.7,
compose services `spa-app` and `keycloak-idp`). This is a permanent regression
target, and the shape is the one a friend's engagement failed on.

* Every non-API path on `http://spa-app:8000` is a catch-all `200 index.html`
  containing `<div id="root">` and one script. It has no `<form>` and no `<input>`.
* `GET /api/auth/login` answers `302` to
  `http://keycloak-idp:8080/realms/northwind/protocol/openid-connect/auth`, a
  different host and port, using authorization code + PKCE with `state` bound to
  a cookie.
* The password form exists only on the IdP. Its action carries one-time
  `session_code` / `execution` / `tab_id` and needs the IdP's `AUTH_SESSION_ID`.
* The SPA sets `nw_session` only on the code exchange, and no token ever appears
  in a body. `/api/me` is the boundary: 401 anonymously, 200 with a session.
* Keycloak runs in production mode (`start`) with direct access grants OFF, so
  the password grant is not available as a shortcut.

The fixture was proven by hand before the engine ran: a curl walk from
`clinkz-tools` reaches `/api/me` 200 as both accounts.

## Cold run: `clinkz scan`, current main's auth path, no declarations

Engagement `7cc8112d`. Scope is `http://spa-app:8000` only, with two roles
(alice, privilege 0; bob, privilege 10). **Exit 3: aborted at authentication.**
The auth path is byte-identical to `904965a`; the branch it ran on changes only
exploit ranking and tracing.

### Where it abstained

| layer | outcome |
|---|---|
| `detect_auth_mechanism` | `none`, login URL not found. It never GETs `/api/auth/login` (its API probe is an empty-credential POST, and the route answers POST with 404), so the one route that starts the login was never observed by the deterministic layer |
| deterministic credential pass | **5 credential POSTs per account, none to a proven login**: 3 to the site ROOT (`login_url` fell back to `base_url`) and 2 to `/rest/user/login`, a canned route this origin answers with the shell's 405. The 6th was held back by the adaptive reserve |
| adaptive layer | **engaged** for both roles, 6 rounds each, **0 credential POSTs**, 0 refusals, abstained. `bob`'s turn 6 reached `GET /api/auth/login` → 302 to the IdP, and then the round budget ran out |
| `walk_redirects` | **never asked.** Nothing on the cold path requested the IdP hop: adaptive READs record a 302 and do not follow it, and the run's scope ledger says "no out-of-scope target was reached for" |

### Is the operator-facing reason true? Bullet by bullet

| bullet | verdict |
|---|---|
| `Auth mechanism: none` / `Login URL: (not found)` | **True but incomplete.** No login lives on this origin. The login *entry* does (`/api/auth/login` → IdP), and the message never says so |
| "a credential POST WAS dispatched … posted to: http://spa-app:8000" | **True, and it is itself a defect** (D1): the root was never shown to be a login |
| "answered 405, which is the server refusing the request rather than issuing a session" | True |
| "no `<form>` … the field names and the destination were taken from loose inputs" | **False in its second half** (D5): the shell has no inputs at all. The sentence fires on `not page_declared_a_form` alone |
| "Server: nginx" | True. The header is what the fixture sends |
| adaptive: "6 safe reads … no credential POST was ever proposed within the gate's bounds" | True |
| "Fix one of: the credentials are wrong, or the account is locked" | **False** (D2). No destination that could judge the credentials ever saw them; a 405 demonstrably changed nothing (invariants 91 and 99) |
| "the login URL is wrong (set `login_url`)" | **Misleading** (D3). Following it, `login_url=…/api/auth/login`, still cannot seat (see below), and the message never names the out-of-scope IdP origin that the adaptive transcript itself recorded |

### With the remedy applied (`login_url` declared at the entry point)

`walk_redirects` **refuses the IdP hop**: `SCOPE REFUSAL: GET …/api/auth/login was
answered 302 redirecting to http://keycloak-idp:8080/…`. Zero credentials are
sent. The adaptive gate refuses the model's `GET` of the IdP's
`.well-known/openid-configuration` as `out_of_scope`, so the scope boundary holds
at both seams. That is correct behaviour, and it is also why this shape is a
**declared boundary rather than a regression**: the login lives on an origin the
operator did not authorise.

## Defects the fixture surfaced

**Status, 2026-10-09:** D1, D2, D3 and D5 are CLOSED by invariants 117 and 118.
D4 is OPEN. Re-run cold, the fixture sends **zero** credential POSTs. The abort
names `GET /api/auth/login → 302 http://keycloak-idp:8080/…` as an off-scope
sign-in, and its only remedy is the scope / supplied-session one. Every line of
the message grades true against the table above:

* the login-URL line now reads `(none observed)` and names the entry and the IdP;
* the role line says no credential was offered (the governor counted zero);
* the 405 line and the "loose inputs" line are gone, because nothing was posted
  and the shell has no inputs;
* `Server: nginx` and the adaptive summary are unchanged and true;
* "the credentials are wrong" and "set `login_url`" are gone.

The landing page's script literals are now login-discovery candidates, which is
how `/api/auth/login` was reached deterministically. D4 is untouched: the model's
READ still sees only the body's shape.

* **D1. Credentials go to unproven destinations.** `_establish_authenticated_state`
  calls `_authenticate_role(cred, detection.login_url or discovered_login or
  base_url)`. "Nothing proven ⇒ `None`, never the root URL" holds in detection
  and is undone at the call site. The JSON arm then spends the account budget on
  canned routes the empty-credential probe had already seen fail.
* **D2.** The abort remedy says "credentials wrong / account locked" after a POST
  that demonstrably changed nothing.
* **D3.** The abort does not name the separate-origin redirect, the one
  observation that explains the failure and points at the remedy
  (operator-supplied session, Part 1; or a declared IdP origin, Part 2).
* **D4.** An adaptive READ returns the response's SHAPE (`1374 bytes of non-JSON
  body`), not its text. The model read `app.js` twice and could not see the
  literal `/api/auth/login` in it. The JS miner's domain is HTTP callees, so
  `window.location.assign(...)` is outside it as well.
* **D5.** The "loose inputs" observation is asserted without an input.

## Fixture notes

`http.server` answers an unimplemented verb with 501, which no nginx front does,
and the cold run's model reasoned from those 501s. The fixture now answers
OPTIONS/PUT/PATCH/DELETE with 405 + `Allow`. The classification above does not
depend on the change. Rebuilding `spa-app` no longer restarts Keycloak.
