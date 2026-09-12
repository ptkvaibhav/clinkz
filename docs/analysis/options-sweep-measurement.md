# The OPTIONS sweep on cal.diy — measured

**Measurement only, 2026-09-12, tree at `85f3c0e`.** Answers the falsifiable
prediction left open in
[`spa-write-surface-blocker.md`](spa-write-surface-blocker.md) §5.2: *did the
`OPTIONS` sweep run on cal.diy, and what did the target answer?*

**Answer: it ran, it worked, and the target names no write verb on any route.
The write-surface gap is a discovery problem, not a wiring fix.**

---

## 1 · The recorded engagement could not answer it, and that is its own finding

Engagement `e4814440` (cal.diy, `http://127.0.0.1:3100`, 46 endpoints) holds
**no record of the sweep either way**:

* `outputs/e4814440-…/tool_invocations/` is **empty — 0 files**, against 2,506
  for the docker-mode Juice Shop run `47c9bd5c`.
* `trace.jsonl` carries 169 rows and **zero `scan`/`agent_step` rows** (recon
  has 4). The scan phase's only entries are three `llm_call` rows.
* `_learn_api_schemas` reports through `self._logger.info` and emits no trace
  event, so its outcome is not in the bundle at all.

**Cause of the empty `tool_invocations/`.** The invocation record is written by
`ToolBase._emit_trace_records`, called only from `_run_subprocess` /
`_run_subprocess_stdin`. Under `TOOL_EXEC_MODE=local` the `http_client` tool
serves requests in-process through aiohttp and **spawns no subprocess**, so no
record is written. Every HTTP request in a local-mode run is therefore
unauditable after the fact — which is why the earlier allocation measurement
recorded *"per-class request counts are NOT recoverable"*.

So the question was answered by **re-running the sweep live**, over the same 46
endpoints recovered from `clinkz.db`.

---

## 2 · It ran — the gate could not have fired

`_learn_api_schemas` has exactly one gate, `self._budget_exhausted()`, and the
tool it needs (`http_request` → `http_client`) is in `ToolResolver.
_ALWAYS_AVAILABLE`. There is no other condition.

| quantity | value |
|---|---|
| scan phase, `e4814440` | `12:05:16` → `12:08:33` = **197 s** |
| `SCAN_TIME_BUDGET` default | **900 s** |
| headroom at the sweep's call site | **~703 s** |
| measured cost of 40 sequential `OPTIONS` probes | **0.11 s** |

`_budget_exhausted()` was false by three orders of magnitude. The call site
(`scan.py:652`) is reached before `HTTPScanResult` is returned, and the 46
endpoints did reach the state store, so the enclosing method returned normally.
**The sweep ran.**

Two observations about the gate itself, neither of which changes the result:

* `_learn_api_schemas` uses `_budget_exhausted()`, not `_budget_allows()`. The
  crawl and fuzz sites use `_budget_allows` precisely so work that takes real
  time is not *started* with a second left. The sweep can begin with 1 s of
  budget and spend two round-trip sets past the deadline. At 0.11 s for 40
  probes this is not urgent, but it is the inconsistent one of the two.
* The sweep's outcome reaches only a log line. A round that wants to know
  whether it ran should not have to re-run it.

---

## 3 · What the target answered — all 44 routes

The 46 endpoints collapse to **44 distinct routes** (`_route_key` strips query
and fragment). Every route was probed with `OPTIONS`, and separately verified
with a raw aiohttp request outside the engine — **status and `Allow` matched the
engine's probe on every route**, so what follows is the target's behaviour, not
an artefact of `_safe_method_probe`.

| what came back | routes | verbs parsed | write verbs |
|---|---|---|---|
| `400`, `Allow: HEAD` | **40** | `HEAD` | **0** |
| `400`, no `Allow` header at all | **3** | — | **0** |
| `204`, `Allow: GET, HEAD, OPTIONS` | **1** | `GET, HEAD, OPTIONS` | **0** |
| **total** | **44** | — | **0** |

`Access-Control-Allow-Methods` was absent on all 44 — nothing for the
deliberately-not-read CORS path to have mis-read even if it were read.

The three that returned no `Allow` at all are the three that matter:

```
400  (no Allow)   /                     GET -> 307
400  (no Allow)   /api/book/event       GET -> 400 {"message":"Either eventTypeId or eventTypeSlug must be provided"}
400  (no Allow)   /api/trpc             GET -> 404
204  Allow: GET, HEAD, OPTIONS   /api/logo    GET -> 200
```

`/api/book/event` and `/api/trpc` are cal.com's booking and tRPC entry points —
the two routes on this target that certainly accept writes. Both answer `OPTIONS`
with `400` and **no `Allow`**. The one route that answers correctly, `/api/logo`,
is a read-only handler and says so truthfully.

Two `GET`-only spot checks on routes the crawl never found confirm the pattern
is systemic rather than specific to those two:

```
OPTIONS 400 (no Allow) · GET 200    /api/auth/session
OPTIONS 400 (no Allow) · GET 200    /api/auth/providers
```

**The target is a production build** — `caldiy-calcom-1` runs
`scripts/start.sh` → `yarn start` with `NODE_ENV=production` — so this is not
dev-server behaviour that a real deployment would not show.

---

## 4 · Why the verbs that DID come back never reached the endpoint model

They were parsed correctly and then correctly discarded. 41 of 44 routes yielded
a parsed verb list; `learn_allowed_methods` emits an `Endpoint` only for

```python
if method in known or method not in _WRITE_METHODS:   # ("POST", "PUT", "PATCH")
    continue
```

and **not one of the returned verbs is a write verb** — 40 routes said `HEAD`,
one said `GET, HEAD, OPTIONS`. `learn_allowed_methods` returned **0 new
endpoints**, which is the right answer to what the target said.

Nothing was dropped that should have been kept. There is no wiring defect on
this path.

---

## 5 · The one real bound, and how close it came

`MAX_OPTIONS_PROBES = 40` against **44 routes**, so 4 were not probed. The
selection is `sorted(by_route)[:40]` — lexicographic over the full URL — and
that ordering is load-bearing on a Next.js target:

* `_` (0x5F) sorts before `a` (0x61), so **every `/_next/static/chunks/…` route
  sorts ahead of every `/api/…` route**.
* 32 of the 44 routes here are JS/CSS chunks. They consumed **32 of the 40
  probes (80%)** and can never declare a write verb.
* The 4 routes cut were `favicon.ico`, `ring.mp3`, `safari-pinned-tab.svg`,
  `site.webmanifest` — all static. **Truncation cost nothing on this run.**
* But `/api/book/event`, `/api/logo` and `/api/trpc` sat at sorted indices
  **33, 34, 35** — inside the budget by six slots. A crawl that had found **41**
  chunks instead of 32 would have spent the entire budget on bundles and probed
  **no application route at all**, silently. cal.com's login page alone
  references 31 chunks.

So the budget is a live constraint that did not bind here and would bind on a
slightly larger bundle set, in the worst possible way: the routes it drops are
exactly the ones the sweep exists to find.

---

## 6 · What this decides

**The write-surface work is a discovery problem, not a wiring fix.** Producer 5
of `spa-write-surface-blocker.md` §2 is sound, ran, and is **exhausted on this
target class**: production Next.js emits `Allow` only where a Route Handler
module's exported methods generate it (`/api/logo`), and emits nothing for the
Pages-API and catch-all routes that carry the writes. Unlike Express + `cors`,
Django or Rails, there is no framework-level `OPTIONS` responder to interrogate.

This is a measured boundary, not a bug to fix. Building more of producer 5 buys
nothing on this target shape.

What it does **not** license:

* Not a reason to read `Access-Control-Allow-Methods` as an inventory. It was
  absent on all 44 routes here, and the reason it is not read is unchanged.
* Not a reason to relax the write gate to admit `GET` endpoints — §5.4 of the
  blocker doc stands.
* Not a reason to send a write to find out what a verb is. Invariant 21 held
  throughout: every request in this measurement was `GET` or `OPTIONS`, and
  `_safe_method_probe` refuses anything else at the seam.

The work moves to **producer 3** (`JSCallSiteDiscoverer`) and its two separable
defects — bundle *coverage* (12 of ~31) and method *readability* (the
`if method is None: method = "GET"` fallback at `_js_api_mining.py`, plus the
tRPC shape where the method lives in link configuration and never at the call
site). The two model sites that assert `GET` where nothing was read
(`_js_api_mining.py:800`, `_route_discovery.py:493`) are the §6-law half of
that, and this measurement is what says they are now the binding constraint.
