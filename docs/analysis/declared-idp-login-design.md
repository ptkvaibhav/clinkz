# Part 2 — logging in through a DECLARED identity provider (design only)

**Status: design, priced against `docker/spa-keycloak`. Nothing here is built.**
Part 1 (`RoleCredential.session`) already covers every IdP, including MFA,
CAPTCHA and WebAuthn, at the cost of expiry. Part 2 is worth building only for
what Part 1 cannot do: an engagement long enough that a browser session expires,
or a re-authentication the run must perform itself.

## 0. The rule this design starts from

**The IdP origin enters scope only by explicit operator declaration.** It is
never inferred from a redirect, a discovery document, a `Location` header or a
model proposal. Today all four would be refused, and the cold classification
showed both seams holding: `walk_redirects` refused the 302, and the adaptive
gate refused the model's `.well-known` read as `out_of_scope`
([`spa-separate-origin-idp.md`](spa-separate-origin-idp.md)).

The declaration is **narrower than a scope entry**. The engine may AUTHENTICATE
on an IdP. It may not TEST one. An IdP is usually shared infrastructure the
client does not own, and authorising a login through it says nothing about
authorising an attack on it.

```json
"identity_providers": [
  {"origin": "https://login.example.com",
   "purpose": "authentication_only",
   "declared_by": "…", "declared_reference": "…"}
]
```

It lives on `EngagementScope` (it is scope, not a credential) and is rendered in
the dry run and the report beside the targets. The domain is computed: there is
one predicate, `in_auth_scope(url)`, and exactly one caller class, the auth
exchange. Recon, crawl, scan, research, exploit and the browser oracle consult
`in_scope`, which the declaration does not touch. An AST assertion pins that no
other module reads `identity_providers`.

## 1. The exchange, step by step on the fixture

| # | request | origin | what the engine must do | exists today? |
|---|---|---|---|---|
| 1 | `GET /api/auth/login` | target | observe the 302; carry `nw_login_state` (Path=`/api/auth`) | yes (`walk_redirects`) |
| 2 | `GET …/openid-connect/auth?…` | **IdP** | follow the hop, but only because it is declared | **no**: needs `in_auth_scope` passed as the walk's scope gate |
| 3 | parse the IdP login form | IdP | read `<form action>` (carries `session_code`/`execution`/`tab_id`), field names | yes: Keycloak's form is server-rendered |
| 4 | `POST …/login-actions/authenticate` | **IdP** | the CREDENTIAL POST, now to the IdP; budget keyed on IdP origin + account | partially: the budget keys on origin already; the destination is new |
| 5 | 302 → `…/api/auth/callback?code=…&state=…` | target | follow as a bodyless GET (302 degrades); carry `nw_login_state` | yes (degrade rule), provided the jar is path-aware |
| 6 | callback 302 → `/` + `Set-Cookie: nw_session` | target | **session evidence is the target-origin delta**, not the IdP's `KEYCLOAK_IDENTITY` | **no**: see §2 |
| 7 | `assert_authenticated` on `/api/me` | target | unchanged | yes |

## 2. What it costs

1. **A jar keyed by origin AND path (medium).** The engine flattens cookies to
   `dict[name, value]`. Step 1's `nw_login_state` is `Path=/api/auth`, and steps
   2–4 carry the IdP's `AUTH_SESSION_ID`/`KC_RESTART`. Sending the IdP's cookies
   to the target, or the target's to the IdP, is a cross-origin session leak.
   The adaptive layer already keys its jar by origin (invariant 102), and this
   generalises that jar.
2. **A login verdict decided at the END of a chain (medium-high).**
   `_login_verdict` judges one response. Here the credential POST (step 4)
   answers 302 with IdP cookies, and the session appears two hops later on
   another origin. The verdict must read the target-origin `Set-Cookie` delta
   across the whole chain (invariant 91's delta, re-scoped). An IdP cookie
   never counts as target session evidence: it is what invariant 91 means by a
   cookie issued to any caller.
3. **The IdP's failure vocabulary (small).** A wrong password answers 200 with
   the form again and "Invalid username or password." `classify_lockout` and
   the marker oracle take a control body already (invariant 98). The control is
   the IdP form fetched with no credential, so it costs one GET.
4. **Redaction of OAuth artefacts (small, mandatory).** `code` and
   `session_code` are short-lived credential equivalents. `state` and the PKCE
   values are not secrets but identify a login. All are query values on URLs
   the action log and trace record, and the cold run already printed `state`
   and `code_challenge` verbatim. Redact by parameter NAME at the producer, for
   `code`, `session_code`, `id_token`, `access_token` and `refresh_token`.
5. **Re-authentication (small, once 1–2 exist).** The same chain re-run. With
   the IdP's SSO cookie held, step 2 short-circuits to step 5 without a
   credential, and that cookie must be registered for redaction like a session.
6. **Disclosure (small).** The report gains "authenticated through the declared
   IdP `https://login.example.com`; N requests were sent to it, all part of the
   login exchange". The action log tags each IdP request as `auth_exchange`.

Rough size: one module (`engagement/idp_login.py`, ~600–900 lines) plus the jar
generalisation, a scope field, and the redaction rule. Acceptance means the
fixture seats both roles with no supplied session, re-authenticates after a
`spa-app` restart, the IdP sees only auth-exchange requests, and the five
existing targets are byte-identical.

## 3. What the fixture cannot price, and what stays Part 1's

* **JavaScript-rendered IdP login pages** (Okta Identity Engine's widget,
  recent Auth0 Universal Login, Azure AD B2C custom flows). There is no form
  in the HTML. Driving one means a browser that FILLS and SUBMITS, and
  invariant 25 says nothing is clicked, filled or submitted. That carve-out is
  a separate decision, not part of this design.
* **MFA / TOTP, CAPTCHA, WebAuthn, consent screens, federated upstream IdPs**
  (Keycloak → Google). These are out of scope for an unattended engine by
  construction, and Part 1 is the answer.
* **Device-bound or DPoP tokens.** A supplied session fails these too, so they
  are a stated limitation.

## 4. Order of work, if built

1. Redaction of OAuth query artefacts. This is worth doing now regardless,
   because the cold run already writes them.
2. The `identity_providers` declaration plus the `in_auth_scope` predicate and
   its AST domain assertion, with no behaviour change until 3 lands.
3. The origin-and-path jar.
4. The chain verdict.
5. Re-authentication and disclosure.
