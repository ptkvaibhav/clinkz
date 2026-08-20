# Methodology reference

Per-vulnerability-class forensic detail — the honesty oracle, the phantom fixes
that actually bit us, live-validation notes, and N/A-by-construction reasoning for
each `_test_*` methodology. Relocated here from `CLAUDE.md` so it is **fetched on
demand** rather than loaded into every session; `CLAUDE.md` keeps a one-line
summary + a pointer to each of these files. Nothing was dropped in the move.

## The shared adaptive patterns (W2.1)

All 24 `_test_*` methods are adaptive multi-phase methodologies, not deterministic
one-shot skills:

- **Payload-injection family** — six-phase reflection / fingerprint / synthesize /
  verify pattern with LLM-driven payload synthesis:
  `_test_xss_reflected`, `_test_xss_stored`, `_test_xss_dom`, `_test_sqli`,
  `_test_nosqli`, `_test_ssti`, `_test_xxe`, `_test_cmdi`, `_test_lfi`,
  `_test_file_upload`, `_test_idor`, `_test_open_redirect`,
  `_test_javascript_attacks`.
- **Behavioral family** — four-phase hypothesis / observe / analyze / emit
  pattern: `_test_csrf`, `_test_brute_force`, `_test_weak_session`,
  `_test_security_headers`, `_test_csp`, `_test_crypto`,
  `_test_input_validation`, `_test_secrets_exposure`, `_test_mass_assignment`.

The **deterministic check GATES the LLM**: the LLM reasons/ranks/synthesizes; a
deterministic signal decides emission. When phase-2 has empirically confirmed the
primitive, phase-4 **prefers the deterministic build and skips the LLM** for that
type.

Five of the behavioural family go further and **make no LLM call on the verdict
path at all** — `security_headers`, `csrf`, `weak_session`, `brute_force`, and
`js_attacks`'s classifier. Their inputs are fully observed and every rule is a
pure function of them, so the model was answering a question the code could
already answer while remaining a surface on which a model change re-baselines the
class silently. Each carries a test asserting the model is not *called*. The
measurements that justify each removal — including the `brute_force` one that was
a fabrication surface in evidence rather than a determinism nuance — are in
[deterministic-verdict-classes.md](deterministic-verdict-classes.md). See `.claude/skills/clinkz-dev/honesty-patterns.md` for the full per-vuln
oracle set.

## Classes

| Class | Doc |
|---|---|
| SQLi (+ cookie/session vectors) | [sqli.md](sqli.md) |
| Authentication bypass (D8, `InjectionType.AUTH_BYPASS`) | [auth-bypass.md](auth-bypass.md) |
| NoSQL injection | [nosqli.md](nosqli.md) |
| SSTI | [ssti.md](ssti.md) |
| XXE | [xxe.md](xxe.md) |
| Command injection | [cmdi.md](cmdi.md) |
| LFI | [lfi.md](lfi.md) |
| XSS | [xss.md](xss.md) |
| IDOR | [idor.md](idor.md) |
| Open redirect | [open-redirect.md](open-redirect.md) |
| CSRF | [csrf.md](csrf.md) |
| Brute force | [brute-force.md](brute-force.md) |
| File upload | [file-upload.md](file-upload.md) |
| Weak session | [weak-session.md](weak-session.md) |
| Client-side security logic (WSTG-CLNT-11) | [client-side-logic.md](client-side-logic.md) |
| JWT (Tier-2) | [jwt.md](jwt.md) |
| SSRF (Tier-2) | [ssrf.md](ssrf.md) |
| CSP bypass | [phase3-new-classes.md](phase3-new-classes.md) |
| Cryptography (recovered / forged token) | [phase3-new-classes.md](phase3-new-classes.md) |
| Input validation (client-only constraints) | [phase3-new-classes.md](phase3-new-classes.md) |
| Secrets & configuration exposure | [phase3-new-classes.md](phase3-new-classes.md) |
| Mass assignment / privesc on create | [phase3-new-classes.md](phase3-new-classes.md) |
| Business logic: workflow sequence bypass | [chaining-and-business-logic.md](chaining-and-business-logic.md) |
| Business logic: numeric constraint violation | [chaining-and-business-logic.md](chaining-and-business-logic.md) |
| Business logic: single-use action replayed | [chaining-and-business-logic.md](chaining-and-business-logic.md) |

## Cross-cutting

| Topic | Doc |
|---|---|
| Out-of-band confirmation (P6) | [out-of-band-p6.md](out-of-band-p6.md) |
| The never-sent control arm (every marker oracle) | [never-sent-control.md](never-sent-control.md) |
| Three oracles rebuilt on their defining effects (the arms that fired) | [defining-effect-oracles.md](defining-effect-oracles.md) |
| Client-side execution confirmation (P7) | [client-side-execution-p7.md](client-side-execution-p7.md) |
| Chaining (the decoy control) + business logic + the benchmark profile | [chaining-and-business-logic.md](chaining-and-business-logic.md) |
| Carriers / request builder / planning / dispatch / emission integrity | [exploit-engine.md](exploit-engine.md) |
| DVWA per-level honesty (the phantom control) | [dvwa-per-level-honesty.md](dvwa-per-level-honesty.md) |
| The SQLi context ladder, measured (110 rungs, 0 confirmations) | [dvwa-sqli-context-ladder.md](dvwa-sqli-context-ladder.md) |
| D1 Phase-3 consistency + the honest per-level baseline | [d1-consistency-and-baseline.md](d1-consistency-and-baseline.md) |
| Classes whose verdict asks no model (and the measurements that removed the call) | [deterministic-verdict-classes.md](deterministic-verdict-classes.md) |

The gray-box discovery engine (Δ-capability model, capability classes, capability
learning, cross-language, cross-service) lives under `docs/discovery-engine-*.md`.
