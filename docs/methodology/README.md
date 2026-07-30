# Methodology reference

Per-vulnerability-class forensic detail — the honesty oracle, the phantom fixes
that actually bit us, live-validation notes, and N/A-by-construction reasoning for
each `_test_*` methodology. Relocated here from `CLAUDE.md` so it is **fetched on
demand** rather than loaded into every session; `CLAUDE.md` keeps a one-line
summary + a pointer to each of these files. Nothing was dropped in the move.

## The shared adaptive patterns (W2.1)

All 19 `_test_*` methods are adaptive multi-phase methodologies, not deterministic
one-shot skills:

- **Payload-injection family** — six-phase reflection / fingerprint / synthesize /
  verify pattern with LLM-driven payload synthesis:
  `_test_xss_reflected`, `_test_xss_stored`, `_test_xss_dom`, `_test_sqli`,
  `_test_nosqli`, `_test_ssti`, `_test_xxe`, `_test_cmdi`, `_test_lfi`,
  `_test_file_upload`, `_test_idor`, `_test_open_redirect`,
  `_test_javascript_attacks`.
- **Behavioral family** — four-phase hypothesis / observe / analyze / emit
  pattern: `_test_csrf`, `_test_brute_force`, `_test_weak_session`,
  `_test_security_headers`.

The **deterministic check GATES the LLM**: the LLM reasons/ranks/synthesizes; a
deterministic signal decides emission. When phase-2 has empirically confirmed the
primitive, phase-4 **prefers the deterministic build and skips the LLM** for that
type. See `.claude/skills/clinkz-dev/honesty-patterns.md` for the full per-vuln
oracle set.

## Classes

| Class | Doc |
|---|---|
| SQLi (+ cookie/session vectors) | [sqli.md](sqli.md) |
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

## Cross-cutting

| Topic | Doc |
|---|---|
| Out-of-band confirmation (P6) | [out-of-band-p6.md](out-of-band-p6.md) |
| Carriers / request builder / planning / dispatch / emission integrity | [exploit-engine.md](exploit-engine.md) |
| DVWA per-level honesty (the phantom control) | [dvwa-per-level-honesty.md](dvwa-per-level-honesty.md) |
| The SQLi context ladder, measured (110 rungs, 0 confirmations) | [dvwa-sqli-context-ladder.md](dvwa-sqli-context-ladder.md) |
| D1 Phase-3 consistency + the honest per-level baseline | [d1-consistency-and-baseline.md](d1-consistency-and-baseline.md) |

The gray-box discovery engine (Δ-capability model, capability classes, capability
learning, cross-language, cross-service) lives under `docs/discovery-engine-*.md`.
