# Discovery engine — slice A2b: JS-source generalization, live-proven on OWASP Juice Shop

**Status:** live-validated end-to-end (real Juice Shop v19.1.1 + live OOB collaborator +
live Anthropic exploit LLM, no harness). Generalization claim **only** — the
carrying-dependency write-back keying and JS→JS transfer are a separate follow-up (A2a).

## Claim

The discovery engine + the JS source ingestor generalize to a **real, varied,
different-language, non-Vulhub** target: they surface and live-confirm one of Juice
Shop's **own-code** vulns through the JS-source path — the *same* engine, catalog,
intent, reachability, hypothesis and (unchanged) proof primitives that carry the Java
CVEs, driven by a JS `SourceModel`.

```
Juice Shop TS/ESM source ──JsSourceIngestor(cross-file factory resolution)──▶
  DiscoveryEngine.discover ──▶ EGRESS_FETCH hypothesis
  (POST /profile/image/url · imageUrl · _test_ssrf · js.http_egress) ──▶
  UNCHANGED proof engine ──P6 out-of-band──▶ CONFIRMED on the live instance
```

## Diagnosis (gated the slice) — A1 reaches nothing on real Juice Shop

Running the **A1** (inline-handler) ingestor over the real Juice Shop backend surfaced
**zero** sinks:

```
files_ingested=635  entrypoints=19  call_sites=0 (EGRESS=0 FILE_READ=0)  coverage=ABSENT
```

Root cause: Juice Shop is TypeScript/ESM with a **factory-per-file** handler pattern —
**51 of ~53** route handlers are `export function X () { return (req, res) => {…} }` in a
separate `routes/*.ts` file, registered (often wrapped) in `server.ts`:

```ts
app.post('/profile/image/url', uploadToMemory.single('file'), utils.asyncHandler(profileImageUrlUpload()))
app.use('/ftp(?!/quarantine)/:file', servePublicFiles())
```

A1 assumed an **inline body** immediately after the route and **excluded `app.use`**, so
it never scanned the files where the sinks live. The sink idioms themselves
(`fetch(url)`, `res.sendFile`) were already A1-recognized — only the cross-file structure
blocked them (the "named-handler / controller-module indirection" A1 deferred).

**Target choice = the SSRF, not the file-read.** `routes/profileImageUrlUpload.ts` does
`const url = req.body.imageUrl; … await fetch(url)` — pure A1 idioms once the body is
reachable. The `/ftp/:file` file-read is a worse target: destructured arrow-param
(`({ params }) =>`) + inner helper + allowlist guard, **and it is confined**
(`if (!file.includes('/'))` blocks traversal → no `/etc/passwd` → the P3 content oracle
would not confirm it).

## The hardening (minimal, bounded, no Layer-1 change)

Cross-file **factory-handler resolution** — a second pass, the JS analogue of the Java
ingestor's existing 2-pass cross-file resolution (no AST, no dataflow):

- **Pass 1** indexes every `export function <Name> (...) { … }` body by name.
- **Pass 2** resolves each route registration to its handler body — inline (A1 shape,
  unchanged) or a referenced factory `name()` from the pass-1 registry, across files;
  sink line numbers resolve against the routes file the sink lives in.
- `_RE_ROUTE` now includes `use` (a bare `app.use(mw)` without a path literal is still
  never a route).

Deferrals kept shallow (documented): request destructured in the arrow *param* signature
rather than `req.*`; a *bare* (un-called) handler reference; multi-hop / inner-function
taint; SSRF host-check guards. **No** PrimitiveClass / oracle / proof / recall /
write-back change — the JS ingestor only surfaces JS sink *shapes* that reduce to the
existing primitives.

Deterministically locked by `tests/test_discovery/test_js_ingest_esm_factory.py` (a clean
minimal reproduction of the ESM/factory shape — not a copy of Juice Shop code); A1 fixture
+ Java byte-identical regression unregressed.

## Live validation (real run, no harness) — engagement `cfc21060`

Gray-box **honesty**: the running instance is **v19.1.1**, so the ingested source is the
running container's OWN source (`docker cp clinkz-juiceshop:/juice-shop`), not the cloned
main. The 19.1.1 SSRF handler is byte-identical in shape (`fetch(req.body.imageUrl)` @
`routes/profileImageUrlUpload.ts:24`).

Pre-flight (STOP-on-fail, all passed): Anthropic key present + quota live-pinged; Juice
Shop reachable; source ingests to the EGRESS_FETCH hypothesis; collaborator healthy
(DNS+HTTP self-round-trip). The SSRF is auth-gated, so the driver registers + logs in a
throwaway user for a valid `token`.

Raw result (`scripts/live_juiceshop_ssrf_discovery.py`, artifacts in
`outputs/js-juiceshop-a2b/`):

- **Source → hypothesis** (the JS-source path):
  `sink: fetch(imageUrl) @ profileImageUrlUpload.ts:24 · sink_shape_id=js.http_egress ·
  hypothesis: POST /profile/image/url · param=[imageUrl] · loc=form_body · test=_test_ssrf`
  (Juice Shop parses the body via `bodyParser.urlencoded`, so `imageUrl` rides form-body —
  exactly the location the reachability layer emitted.)
- **P6 confirm (raw-auditable)** — `confirmed_out_of_band=True`:
  - outbound: `POST /profile/image/url — imageUrl=http://host.docker.internal:18081/bryu2wjujlcecg22ihulf4nrr4`
  - inbound callback: `proto=http host=host.docker.internal:18081 path=/bryu2wjujlcecg22ihulf4nrr4`
    (the SAME nonce)
  - control: a fresh nonce minted but never sent → no callback (`control_bore_nonce=False`)
- **Zero-FP** — the same probe with the auth token stripped: the SSRF gate blocks (not
  logged in) → no callback → `confirmed_out_of_band=False`.
- **report.json** carries the finding *Server-Side Request Forgery (SSRF) —
  blind_oob_confirmed* (HIGH) with **JS discovery provenance**
  (`primitive_class=egress_fetch`, `sink_shape_id=js.http_egress`,
  `reachability_grade=static_confirmed`) and the raw P6 evidence pair in its evidence
  list; `trace.jsonl` carries the nonce and `blind_oob_confirmed`.

**RESULT: PASS.**

## Honest nuances

- **`_test_ssrf` (full black-box methodology) emitted 0** — expected and documented:
  Juice Shop's `imageUrl` SSRF is **blind by design** (streams to a file, 302-redirects,
  no in-band reflection), so the black-box six-phase in-band path justifiably defers. The
  **gray-box discovery path** is what surfaces it from source, and the **P6 OOB primitive**
  — what a blind obligation reduces to — confirms it. This is precisely the value of
  gray-box discovery: it finds and proves what the black-box scan misses.
- **`technology_key=node-js`** (the recon fingerprint), not the carrying dependency
  `express`/the sink lib. A1 emits the carrying-dependency manifest on the `SourceModel`
  (here `express@4.21.0`); wiring the write-back to key on it is **A2a**, deliberately out
  of scope.
- The catalog primitive id is still `egress_fetch.java_openconnection` (the
  language-agnostic EGRESS_FETCH entry, widened to Node/JS in slice A1) — a cosmetic name,
  not a Java dependency.

## Artifacts

`outputs/js-juiceshop-a2b/`: `report_juiceshop_ssrf.json`, `trace_juiceshop_ssrf.jsonl`,
`sourcemodel_excerpt.json` (the surfaced sink + carrier), `live_run_stdout.log`.
Reproduce with `scripts/live_juiceshop_ssrf_discovery.py --source <docker-cp'd source>`.
