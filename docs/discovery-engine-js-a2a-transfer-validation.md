# Discovery engine — slice A2a: JS carrying-dependency keying + JS→JS transfer

> **Raw artifacts:** the `outputs/…` run artifacts cited below are local-only by policy — retained by the operator, not committed to the repo.

**Status:** deterministically proven (present-vs-absent transfer + no-over-transfer),
with the keying and provenance stamp **live-confirmed** on real OWASP Juice Shop
(engagement `c0fe946a`, live OOB collaborator + live Anthropic exploit LLM). Closes
out cross-language slice A.

## Claim

A JS capability is keyed on a carrying dependency **only when the sink is
library-borne** — its source file lives inside a bundled local-path / workspace
dependency. An **app-code** sink stays fingerprint-keyed, so an app-level capability
never becomes falsely library-transferable. A confirmed library-borne capability
**transfers** to a different app that bundles the same package, via the existing
capability-recall path (no recall/relations change). And a discovery finding records
the **actual** confirming primitive (P6 for an out-of-band confirm), not the obligation's
declared expectation.

```
app-A (full)  ──sink in packages/vuln-fetch-lib/index.js──▶ EGRESS_FETCH keyed vuln-fetch-lib@2.3.1
              ──confirm──▶ capability_facts row keyed on the PACKAGE
app-B (partial, sink source withheld, EMPTY KB)  ──▶ 0 egress hypotheses           (cold control)
app-B (partial, sink source withheld, fact recalled) ──▶ 1 egress hypothesis, SEEDED,
              prior_source=capability_recall, keyed vuln-fetch-lib                  (warm — transferred)
```

## The correctness core — per-sink carrying-dependency attribution

The A1 model-level `manifest_technology_key` is *the library the egress used* (else the
backend framework), e.g. `express` on Juice Shop / `axios` on the SSRF fixture. Using it
as the EGRESS_FETCH / FILE_READ fact key would be wrong: those apps call the library from
their **own** code — the missing host-allowlist is app code — so keying on the library
would falsely transfer the app's SSRF to every app bundling that library.

A2a keys per sink instead: `CallSite.carrying_dependency` / `carrying_version` are set
only when the sink's source `file` lives inside a **declared local-path / workspace
dependency** directory (attributed from the sink's path + that package's own
`package.json`). `_technology_identity` returns the sink's attributed carrying dependency
for EGRESS_FETCH / FILE_READ when present, else the unchanged fingerprint;
`LOG_INTERPOLATION` is unchanged. Declared local packages are also surfaced as observed
technology identities, so a package present-per-manifest but source-withheld this
engagement stays recall-observable — the transfer path, riding the **unchanged** recall
(`exact_tech` via an observed identity).

## Deterministic proof (the primary signal) — `outputs/js-a2a-transfer/`

Two-fixture "gets smarter" experiment, JS edition, plus the safety half. Reproduce with
`python scripts/live_js_transfer_a2a_validation.py`.

| Artifact | Evidence |
|---|---|
| `capability_facts_after_A.json` | engagement A write-back → one row keyed `technology_key=vuln-fetch-lib`, `version_predicate==2.3.1`, `primitive_class=egress_fetch` — the **package**, not app-a |
| `hypotheses_cold_control_B.json` | app-B partial source + **empty KB** → `[]` (zero egress hypotheses) |
| `hypotheses_warm_B.json` | app-B same partial source + the recalled fact → one egress hypothesis, `technology_key=vuln-fetch-lib`, `prior_source=capability_recall`, `reachability_grade=hypothesized` (recall does not fake reachability) |
| `no_over_transfer.json` | `js_express_ssrf` (axios app) and `js_express_esm_factory` (Juice-Shop A2b analogue) both key `technology_key=node-js`, `carrying_dependency=""` — app-level sinks stay fingerprint-keyed |

The cold-control(0) vs warm(1, recall-seeded) diff is the deterministic present-vs-absent
"gets smarter" signal; the no-over-transfer file is the safety half. Locked in the keyless
gate by `tests/test_discovery/test_js_transfer.py` (real temp-KB round-trip) and the
`test_js_ingest.py` attribution units.

## No-over-transfer, live on the real target

The real Juice Shop SSRF (`routes/profileImageUrlUpload.ts:24`, `fetch(req.body.imageUrl)`)
is app code, so the ingestor surfaces it keyed on the **fingerprint**, not the library:

```
POST http://localhost:3000/profile/image/url  param=imageUrl  key=node-js  carrying=''  file=profileImageUrlUpload.ts
```

## Provenance truth — live report.json (`outputs/js-a2a-transfer/live_juiceshop_report_finding.json`)

Live engagement `c0fe946a` (real Juice Shop TS source `docker cp`'d from the running
container + live collaborator + live Anthropic): the blind SSRF is confirmed **out-of-band**
(P6 callback bearing the probe nonce, raw-auditable, plus the never-sent control; zero-FP
when auth is stripped). The persisted finding's discovery provenance:

```json
{ "technology_key": "node-js", "primitive_class": "egress_fetch",
  "sink_shape_id": "js.http_egress", "confirmation_primitive": "P6",
  "reachability_grade": "static_confirmed" }
```

`confirmation_primitive` reads **P6** — the ACTUAL out-of-band primitive that confirmed it,
not the EGRESS_FETCH obligation's declared in-band `P3/P1` — and `technology_key` reads
**node-js**, not `express`. Both A2a fixes visible in one raw report.json on a live target.

## Scope fence honoured

No new `PrimitiveClass` / oracle, no proof-engine change, no recall/relations logic
change (recall keys on the fact's stored `technology_key`, which now correctly carries the
package for a library-borne sink). Java / log4j keying unchanged. The change is
`_technology_identity` + the ingestor's per-sink attribution + the provenance stamp.

## Deferred

The optional language-neutral `primitive_id` rename (JS findings still carry
`egress_fetch.java_openconnection`) — skipped to avoid churn across provenance /
`technique_name` / docs / tests. JS→JS transfer via a `bundles` transfer edge (this slice
transfers via the `exact_tech` observed-identity path; the unversioned JS fingerprint has
no `bundles`-eligible app entry). Angular / frontend.
