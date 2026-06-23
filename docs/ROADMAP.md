# Clinkz — Capability Expansion Roadmap

Durable plan-of-record for growing the Exploit agent's vuln-class coverage. This is the
sequence we execute; it is not a backlog of ideas. Keep it lean.

> **Current position:** Tier-2 underway — **JWT attacks shipped** (the first cryptographic,
> non-injection primitive). **Next is SSRF.** The original methodology set was 14, now 18.

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

### CONFIRMED — 18 adaptive methodologies (shipped)
`sqli`, `nosqli`, `ssti`, `xxe`, `jwt`, `xss_reflected`, `xss_stored`, `xss_dom`, `cmdi`, `lfi`,
`file_upload`, `csrf`, `brute_force`, `open_redirect`, `idor`, `security_headers`, `weak_session`,
`javascript_attacks`.

### TIER-1 PRIMITIVES — reuse the six-phase injection family (all shipped)
- ~~**NoSQL injection** — MongoDB-style operator/`$where` injection.~~ *(shipped)*
- ~~**SSTI** — server-side template injection (Pug/EJS/Nunjucks/Jinja2/Freemarker).~~ *(shipped)*
- ~~**XXE** — XML external entity injection (file disclosure / SSRF / bounded DoS).~~ *(shipped)*

### TIER-2 — contained, high-value on modern targets
- ~~**JWT attacks** — alg=none, weak-secret, algorithm confusion, claim tampering, kid injection,
  expired acceptance. Fully in-band (server accepts a forged/tampered token).~~ *(shipped)*
- **SSRF** — server-side request forgery. *(next)*

### HARDER — need a reasoning layer / chaining
- Deserialization → RCE, business-logic flaws, broken-auth flows, crypto misuse.

### SPECIALIZED — Research/KB-driven or domain-specific
- Sensitive-data exposure, security misconfiguration,
  vulnerable-components / supply-chain (Research/KB-driven), prompt-injection.

## Agreed sequence

1. **NoSQL / SSTI / XXE** — nearly free; they reuse the proven six-phase injection pattern
   (map → fingerprint → rank → synthesize → verify → emit). Highest ROI for least new machinery.
2. **JWT / SSRF** — contained, self-confirming, and high-frequency on modern API/SPA targets.
3. **Make Tier-2/3 real** (`_apply_technique`; Research crafts a methodology from KB/web findings) —
   the highest-leverage step: a self-extending capability that covers the long tail without
   hand-coding every vuln class.
4. **Vulnerability chaining** — last. It is multiplicative on the primitives above and needs the
   reasoning layer Tier-2/3 provides (e.g. SQLi → cred dump → auth → upload → RCE).

## Tracking

Each primitive lands as: methodology models (`models/methodology.py`) + six-phase `_test_*`
(`agents/exploit.py`) + wiring (`TIER1_TESTS`, dispatch, applicable-methods) + a Tier-1 seed entry
+ real-target gates (a `*_smoke` test that confirms the vuln on the target's canonical surface, and
a no-false-emission check on a stack where it does not apply).
