# CSRF — `_test_csrf`

Four-phase behavioral methodology (hypothesis / observe / analyze / emit). Emits
only for a state change that alters the victim's **security posture**, gated to
stay honest.

**Phase 3 calls no LLM** (since 2026-08-19). Every input the verdict needs is
observed in phase 2 — the token fields, their values across three fetches, the
`SameSite` directive, whether a token survives a cookie-stripped fetch — and
every rule is a pure function of them. The model was asked anyway across **227
recorded phase-3 calls and changed the verdict zero times**, while remaining a
surface on which a model change could re-baseline the class silently. The
rotating session-bound protection override below still runs first and is
unaffected. See
[deterministic-verdict-classes.md](deterministic-verdict-classes.md).

## Security-sensitivity gate (BUG 3)

`_csrf_is_security_sensitive` (phase 1): emit only for a `DELETE`/`PUT`/`PATCH`
REST verb, an account/email/role/delete/transfer-class keyword in the field names
or the resolved endpoint path (`action_url`, so a JSON pseudo-form like
`/rest/user/change-password` is classified by its path), or a **password
*mutation*** — never a *plain login*. The password signal is **gated on mutation
structure** (`_CSRF_PASSWORD_QUALIFIERS`): a lone `password` field does NOT qualify
on its own (engagement ec39350b sprayed a CSRF finding off DVWA
`/cryptography/index.php`'s single `['password','']` input); it qualifies only with
**≥2 password fields** (new + confirm) OR a change/registration qualifier
(`new`/`current`/`old`/`change`/`confirm`/`update`/`reset`) in a field name or the
path — so `/csrf/` + `/captcha/` (both `password_new`+`password_conf`) and Juice
Shop `/rest/user/change-password` (path token) still confirm while the
lone-password crypto form is a justified non-finding. A bare token-less POST is
therefore NOT a finding, which stops the per-form spray (the f7a761a1
over-emission flagged guestbook/CSP/crypto-encrypt/upload) while the genuine
password-change challenge still confirms.

## Bearer-only guard

A state-changing JSON API authenticated purely by an `Authorization` header (no
ambient cookie) is not CSRF-able, a justified non-finding; a cookie-borne
*sensitive* form with no anti-CSRF token still flags. `_http_post_json` carries
cookies + JWT bearer exactly like `_http_post`.

## Rotating-session-bound-token deterministic override (impossible-level honesty)

`_csrf_token_provides_protection` (phase 3, ahead of the LLM — a *third* honesty
gate): phase 2 already captured DVWA high/impossible's rotating `user_token`, but
the phase-3 LLM ruled it "effectively missing" because it rides via GET. When a
token field is present, rotates across the three fetches (≥2 distinct non-empty),
and is session-bound (absent on the cookie-stripped fetch — phase 2's
`tokens_without_cookies`), force `protected=True`/`weakness=None` before any LLM
call; GET-vs-POST transmission is at most a low-severity note, never "CSRF
missing". Low (no token) / medium (Referer-only) still confirm; high/impossible do
not falsely emit.
