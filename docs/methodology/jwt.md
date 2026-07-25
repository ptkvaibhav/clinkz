# JWT attacks — `_test_jwt`

First Tier-2 primitive. **Not** injection-family — cryptographic token
manipulation — but reuses the six-phase scaffolding (map → fingerprint → rank →
synthesize → verify → emit) with cryptographic content. Uses **PyJWT** for all
token encode/decode/sign — never hand-rolled crypto. Models in
`models/methodology.py` (`JWTAlgorithm`, `JWTAttackType`, `JWTFingerprint`,
`JWTMethodologyResult`).

## Endpoint-scoped carrier

Like XXE it is endpoint-scoped, not parameter-scoped: the *token itself* on an
authenticated request is the injection point, so `_test_jwt` runs once per page
(no `for param` loop); `candidate_param` is a synthetic carrier label
(`authorization_bearer` / `jwt_cookie:<name>`). **New carrier**
`_jwt_send_with_token` sends `Authorization: Bearer <token>` and **drops the
cookie jar** so the only credential under test is the token (otherwise an ambient
session cookie — Juice Shop also sets a `token` cookie — masks whether the forged
token was accepted); the shared `_send_probe`/`_http_*` family is left untouched.

## Phases

- **Phase 1** acquires the JWT (the captured bearer in `_session_headers`, a
  JWT-shaped cookie, or one harvested on the endpoint) and **baseline-anchors**
  that THIS endpoint validates the signature — the valid token is accepted
  (2xx/3xx) AND a broken-signature token is rejected (401/403); if not, it
  declines (so an open/cookie-authed endpoint never yields a phantom). No JWT held
  anywhere ⇒ N/A by construction (DVWA's PHP session cookies).
- **Phase 2** fingerprints the token (algorithm / `kid` / claim **names** /
  privileged claims / expiry — **never claim values**, so the fingerprint is
  redaction-safe).
- **Phase 3** ranks the attack classes (LLM checkpoint, Anthropic-pinned) with
  **hard preconditions enforced regardless of the LLM** (`alg_none` only if
  signed, `algorithm_confusion` only if asymmetric, `weak_secret` only for HMAC,
  `kid_injection` only if `kid` present, `claim_tampering` only if a privileged
  claim exists, `expired_acceptance` only if `exp` present).
- **Phase 4** synthesis is **deterministic** (token signing is cryptographic — an
  LLM cannot produce a valid signature): alg:none strips the signature (+
  `None`/`NONE` case-variant bypasses); `weak_secret` cracks a **bounded**
  common/default-secret list (`_JWT_WEAK_SECRETS`, ~25 entries — proves the secret
  was guessable, never an exhaustive crack) via a local signature check then
  re-signs; `algorithm_confusion` re-signs HS256 with a JWKS-fetched public key
  (in-scope JWKS probe only; declines without one);
  `claim_tampering`/`expired_acceptance` require a cracked key so the elevated/
  back-dated token is *validly signed*.
- **Phase 5 is fully in-band** — the strength of JWT vs the OOB-limited XXE: send
  the forged token to the gated endpoint, confirmed only when it is **accepted
  like the valid baseline** (a success status matching the valid token, diverging
  from the 401/403 reject). A rejected token never confirms. Severity **critical**
  (alg:none / confusion / weak-secret / kid → forgery / full auth bypass) /
  **high** (claim-tampering / expired).

## Redaction + dedup

**Token redaction** (`_jwt_redact`): findings/logs carry only the decoded header +
claim *names* + `<sig elided>` — never the raw token or the cracked secret. Per-
engagement dedup (`_jwt_emitted_attacks`) emits each attack class at most once
(acceptance is a server-wide property).

On Juice Shop the canonical gates are the **Unsigned JWT** (alg:none) and
**Forged Signed JWT** challenges; the `juiceshop_smoke` gate is skip-tolerant
(build-dependent alg:none acceptance). N/A by construction on DVWA (PHP session
cookies, no JWT).
