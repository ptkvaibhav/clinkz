# Discovery engine — cross-language slice A1: JS/TS (Node/Express) source ingestor

**Status:** as-built, deterministically validated (no live target, no LLM in the
ingest path). First cross-language rung toward a Juice-Shop-class Node target.

## Goal

Make the language-agnostic discovery engine work on non-Java targets. The engine's
four downstream layers (catalog → intent → reachability → hypothesis) and the whole
Layer-2 loop (recall / write-back / relations) are keyed on the language-agnostic
`SourceModel`; the **one** language-specific piece is *which ingestor produces it*.
Slice A1 names that seam and adds a JS/TS backend ingestor behind it, with **zero**
behaviour change to Java.

## What was built

### 1. The `SourceIngestor` seam (`discovery/ingestor.py`)

- **`SourceIngestor`** — a minimal `runtime_checkable` `Protocol`:
  `ingest_path(root) -> SourceModel`. Both `JavaSourceIngestor` and
  `JsSourceIngestor` satisfy it *structurally* — the extraction is pure, the Java
  ingestor is untouched.
- **`select_ingestor(root)`** — deterministic per-tree language detection:
  - a root build manifest (`pom.xml` / `build.gradle[.kts]`) or any `*.java` → Java;
  - a root `package.json` or any `*.js/.mjs/.cjs/.ts` → JS;
  - **Java wins ties** (preserves every existing Java target);
  - **Java is the default** when neither is detected — so an empty / non-source
    `source_dir` behaves exactly as before the seam existed.
  - The extension probe skips `node_modules` / build dirs, so a JS project that
    vendors a `*.java` under `node_modules` never mis-detects as Java.
- `DiscoveryEngine.discover` re-points its single ingest call from the hard-wired
  `JavaSourceIngestor()` to `select_ingestor(source_dir).ingest_path(source_dir)`.

### 2. `JsSourceIngestor` (`discovery/js_source_ingest.py`)

A deliberately-shallow, backend-only **mirror** of the Java ingestor's discipline —
regex / bounded-scan-only, source treated as untrusted data, **no `eval`**, bounded
file count/bytes, `node_modules` / build output / `*.min.js` / `*.d.ts` never
ingested (Angular / frontend deferred). It surfaces JS *sink shapes* that reduce to
the **existing** `PrimitiveClass` values — it adds no capability class, oracle or
proof:

| SourceModel field | JS idiom |
|---|---|
| `entrypoints` | Express `app.`/`router.<verb>(path, handler)` route registrations; taint resolved inside the balanced handler body (the inline-handler shape) |
| channels | `req.query` / `req.body` / `req.params` / `req.headers` reads (`req.params` → `path_params`, the URL-path segment) |
| `call_sites` (`EGRESS_FETCH`) | `axios(…)` / `axios.get/post` / `fetch(…)` / `http(s).get/request` / `got` / `request` / `superagent` with a request-tainted URL → `sink_shape_id = js.http_egress` |
| `call_sites` (`FILE_READ`) | `fs.readFile*` / `fs.createReadStream` / `res.sendFile` with a request-tainted path → `sink_shape_id = js.fs_read` |
| `guards` | `path.basename(x)` / `path.normalize(x)` on the tainted path → SANCTIONED (the file-read analogue of Flink's `.getName()` fix; conservative — over-guard, never a phantom) |
| `manifest_technology_key` / `_observed_version` | `package.json` (+ `package-lock`) → the carrying dependency of the surfaced capability (the HTTP-client lib an `EGRESS_FETCH` used, else the backend framework); lockfile version wins over the spec |

Taint is **one hop** (request read → local; a local / inline request read → sink
argument). Multi-hop propagation through a reassignment, named-handler / controller
indirection, and SSRF host-check guards are documented deferrals.

### 3. The one Layer-1 touch (isolated + flagged) — `catalog.py`

`match_primitives` gates a catalogued primitive on **both** the sink class being
present **and** its `technology_pattern` matching the stack. `EGRESS_FETCH` /
`FILE_READ` used a Java-only pattern (`(?i)\bjava\b|servlet`), so a JS `SourceModel`
produced zero active primitives → zero hypotheses.

SSRF egress-fetch and path-traversal file-read are **language-agnostic** capabilities
— the sink shape differs per language (`URL.openConnection` vs `axios.get`;
`new File` vs `fs.readFile`) but the Δ-adjudication, reachability and proof oracle are
identical, and each ingestor surfaces the sink as the *same* `PrimitiveClass`. Both
patterns are widened (single-sourced constant `_MULTILANG_FETCH_FILE_TECH`) to also
match the Node/JS/TS stack. **This adds no PrimitiveClass, oracle, or proof-engine
change** — it only lets an existing primitive apply to a new language.
`LOG_INTERPOLATION` is deliberately **not** widened (Log4Shell is a Java/log4j-core
property, manifest-version-gated; a JS log-injection would be a different class).

## Validation (deterministic, in isolation)

All in `tests/test_discovery/`, keyless — no container, no LLM, no collaborator.

1. **`test_js_ingest`** — over the checked-in `tests/fixtures/js_express_ssrf/`
   Express app:
   - ingestor shapes: `/fetch` + `/download` entrypoints; the `EGRESS_FETCH`
     call-site tainted by `url` (`js.http_egress`, `axios.get`); the `FILE_READ`
     call-site tainted by `file` (`js.fs_read`, `fs.readFile`); the carrying-dep
     manifest `axios @ 1.6.7` (lockfile precedence over the `^1.6.0` spec);
     `Node.js` + `Express` technologies; `PARTIAL` coverage.
   - **full JS-source → engine → hypothesis path**: `match_primitives` activates
     `EGRESS_FETCH` + `FILE_READ` on a `["Node.js","Express"]` fingerprint, and
     `DiscoveryEngine.discover` yields the expected `EGRESS_FETCH` (`/fetch`, `url`,
     `_test_ssrf`) and `FILE_READ` (`/download`, `file`, `_test_lfi`) hypotheses,
     each lowering to an `ExploitTask` for the unchanged plan-union; the manifest
     survives to `result.source_model` for A2's write-back.
   - honesty / generality: a `path.basename` guard → SANCTIONED; a constant
     (non-request) fetch URL → no `EGRESS_FETCH` (N/A by construction); an empty
     tree → `ABSENT`; a `req.params.id` read rides the URL path.
2. **`test_ingestor_dispatch`** — `select_ingestor` routes the Node project to
   `JsSourceIngestor` and every Java fixture to `JavaSourceIngestor`; both classes
   satisfy the `SourceIngestor` protocol; a non-source tree defaults to Java. The
   **Java byte-identical regression** dumps each existing Java fixture's `SourceModel`
   (`model_dump()`) via the dispatch vs the direct `JavaSourceIngestor` call and
   asserts field-for-field equality — the interface extraction did not perturb Java.
3. Full keyless suite green (1553 passed); discovery Java classes
   (log4shell / solr / flink) unregressed.

## Out of scope this slice

- Live target / exploitation (deterministic slice only).
- Any recall / write-back / relations change (already language-agnostic; A2 consumes
  the JS carrying-dependency manifest for the write-back key).
- Angular / any browser-side frontend.
- Multi-hop taint, named-handler indirection, JS SSRF host-check guards.
