# SSTI — `_test_ssti`

Second new Tier-1 primitive. Mirrors the SQLi/NoSQL six-phase injection-family
shape; the carrier is template syntax and the gadgets are engine-specific.
Models in `models/methodology.py` (`SSTITemplateEngine`,
`SSTIExploitationType`, `SSTIPrimitives`, `SSTIMethodologyResult`). SSTI payloads
are **strings**, so the shared `_send_probe` carries them unchanged (no dedicated
carrier, unlike NoSQL).

## Phases

- **Phase 1** sends **polyglot arithmetic probes** (`{{a*b}}`/`${a*b}`/`#{a*b}`/
  `<%= a*b %>`/`{a*b}`) with **randomized factors**; candidacy is *evaluation*
  (the product rendered AND the literal wrapper not reflected verbatim), so
  literal reflection on a non-template stack (DVWA) is correctly N/A.
  **Read-back aware** (`_ssti_observe`, mirroring stored-XSS): a body/form param
  submitted via POST can render its eval second-order on a GET of the page — the
  Juice Shop **Pug `/profile` username** case (`POST /profile` 302-redirects;
  `GET /profile` renders `#{a*b}` → product).
- **Phase 2** fingerprints the **engine** (SSTI's "SQL-dialect"): `#{}`→Pug,
  `<%= %>`→EJS, `${}`→Freemarker, `{{}}`→Jinja2-vs-Nunjucks/Twig via `{{7*'7'}}`
  (`7777777` Python string-repeat vs `49` JS coercion).
- **Phase 4** conditions synthesis **strictly on the fingerprinted engine** (the
  SQLi lesson: don't synthesize for the wrong engine).
- **Phase 5** verification-honest like CMDi: an arithmetic eval must render in a
  normal (sub-400) response; an RCE **echo-canary** (`echo <token>`) must land in
  command-output position — a canary in a 4xx/5xx/error body, or an echoed `echo`
  scaffold, is reflection not execution (reuses `_cmdi_body_has_error` + the
  encoding-robust scaffold guard). Severity **high** (eval) / **critical** (RCE:
  Pug/EJS/Nunjucks Node `child_process` gadget, Jinja2 `__class__` chain,
  Freemarker `Execute`).
- **Phase 3** returns **no candidate type** when nothing evaluates, so SSTI is N/A
  by construction on DVWA — no false emission.

## Literal-reflection coexistence (live-verified fix; LESSONS #22)

Juice Shop's profile renders the username *twice* — the evaluated product in a
`<p>` AND the raw literal in an input `value=` — so eval detection is
**baseline-anchored** (the product must be absent from a benign baseline body,
never gated on "literal present") and RCE confirmation **strips the
`echo <canary>` scaffold** (encoding-robust) so a *bare* canary confirms even
when the whole gadget is also reflected verbatim. The earlier
"reject if the literal/scaffold is anywhere in the body" guard silently
suppressed real findings and was caught only by running against an eval-enabled
instance.

**Juice Shop default-Docker is an expected justified non-finding**: the
username-eval is gated behind `isChallengeEnabled(usernameXssChallenge)`, and
`challenges.safetyMode=auto` + the challenge's `disabledEnv:[Docker]` disables
it, so `#{a*b}` renders literally and nothing emits — verified end-to-end against
a `safetyMode=disabled` instance (high-severity Pug `expression_eval` finding).
