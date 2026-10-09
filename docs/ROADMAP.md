# Clinkz — Capability Expansion Roadmap

Durable plan-of-record for growing the Exploit agent's vuln-class coverage. This is the
sequence we execute; it is not a backlog of ideas. Keep it lean.

> **Current position (verified against the tree 2026-10-09):** 29 per-class methodologies in
> `TIER1_TESTS`, plus discovery-originated `_test_log4shell`. Chaining, business logic, the P6
> out-of-band collaborator and the P7 browser oracle are BUILT. **Tier-2/3 is still not real**:
> `_test_tier2_technique` / `_test_tier3_technique` delegate to `_apply_technique`, which sends no
> request, and both are registered `NOT_IMPLEMENTED`. The original methodology set was 14.

## Guiding principle

Every addition is proven against the target's *real* challenge list (DVWA / OWASP Juice Shop),
exactly the way the original methodologies were. Three non-negotiables:

- **Platform-agnostic** — the methodology shape is the same across stacks; only operators/payloads
  differ (e.g. NoSQL mirrors SQLi's six phases, swapping SQL operators for MongoDB operators).
- **Real-attacker confirmation, not checklist matching** — a finding emits only when its own
  evidence confirms exploitability (reflection-in-error phantoms are rejected).
- **Contract** — if the vuln is present on the target, the method MUST find it; if absent, it must
  not false-positive (e.g. NoSQL is N/A on DVWA's PHP/MySQL stack and emits nothing there).

## Coverage map

### CONFIRMED — 29 adaptive methodologies (shipped)
`sqli`, `nosqli`, `ssti`, `xxe`, `jwt`, `ssrf`, `xss_reflected`, `xss_stored`, `xss_dom`, `cmdi`,
`lfi`, `file_upload`, `csrf`, `brute_force`, `open_redirect`, `idor`, `security_headers`,
`weak_session`, `javascript_attacks`, `csp`, `crypto`, `input_validation`, `mass_assignment`,
`secrets_exposure`, `state_sequence`, `constraint_violation`, `repeatability`,
`prototype_pollution` (TERMINAL), `write_crossing` (TERMINAL). Plus `log4shell` (P6, discovery).

### TIER-1 PRIMITIVES — reuse the six-phase injection family (all shipped)
- ~~**NoSQL injection** — MongoDB-style operator/`$where` injection.~~ *(shipped)*
- ~~**SSTI** — server-side template injection (Pug/EJS/Nunjucks/Jinja2/Freemarker).~~ *(shipped)*
- ~~**XXE** — XML external entity injection (file disclosure / SSRF / bounded DoS).~~ *(shipped)*

### TIER-2 — contained, high-value on modern targets (both shipped)
- ~~**JWT attacks** — alg=none, weak-secret, algorithm confusion, claim tampering, kid injection,
  expired acceptance. Fully in-band (server accepts a forged/tampered token).~~ *(shipped)*
- ~~**SSRF** — server-side request forgery. Coerce the in-scope server to fetch internal/metadata
  addresses (the internal URL rides as a param *value*; Clinkz only ever connects to the in-scope
  target). In-band confirmation — cloud-metadata / IAM signature, `file://` read, or reflected
  internal/loopback content. Blind SSRF is deferred (see OOB collaborator below).~~ *(shipped)*

### OOB collaborator — BUILT for blind SSRF and Log4Shell; blind XXE and blind SQLi still deferred
`oob/collaborator.py` (P6, `docs/methodology/out-of-band-p6.md`) confirms blind SSRF and Log4Shell
by an unforgeable-nonce callback. XXE still filters `OOB_EXFIL` out of its ranking and blind/time-only
SQLi has no OOB arm, so the paragraph below remains true for those two.

A listener service (DNS/HTTP callback, in the Burp-Collaborator / interactsh mould) that confirms a
vuln by an **out-of-band callback** instead of an in-band reflection. **Blind SSRF, blind XXE
(`oob_exfil`), and blind/time-only SQLi all need it** — today each degrades to its in-band path and
emits **nothing** (with a documented `blind_suspected` / limitation note, never a phantom) when the
channel is blind. Deliberately not built yet: it is shared infrastructure, sequenced after the
in-band primitives — and it lifts all three blind paths at once.

### HARDER — need a reasoning layer / chaining
- Deserialization → RCE — not built.
- Business-logic flaws — three classes built; two cannot evidence intent on an action endpoint
  (register R13, UNREACHABLE PRECONDITION). Chaining — built (`src/clinkz/chaining/`).

### SPECIALIZED — Research/KB-driven or domain-specific
- Sensitive-data exposure, security misconfiguration,
  vulnerable-components / supply-chain (Research/KB-driven), prompt-injection.

## Agreed sequence

1. **NoSQL / SSTI / XXE** — nearly free; they reuse the proven six-phase injection pattern
   (map → fingerprint → rank → synthesize → verify → emit). Highest ROI for least new machinery.
2. ~~**JWT / SSRF** — contained, self-confirming, and high-frequency on modern API/SPA targets.~~ *(done)*
3. **Make Tier-2/3 real** (`_apply_technique`; Research crafts a methodology from KB/web findings) —
   **← current focus.** The highest-leverage step: a self-extending capability that covers the long
   tail without hand-coding every vuln class.
4. ~~**Vulnerability chaining**~~ — built ahead of Tier-2/3, graded by its weakest link and
   proven against a decoy (`docs/methodology/chaining-and-business-logic.md`).

## Tracking

Each primitive lands as: methodology models (`models/methodology.py`) + six-phase `_test_*`
(`agents/exploit.py`) + wiring (`TIER1_TESTS`, dispatch, applicable-methods) + a Tier-1 seed entry
+ real-target gates (a `*_smoke` test that confirms the vuln on the target's canonical surface, and
a no-false-emission check on a stack where it does not apply).
