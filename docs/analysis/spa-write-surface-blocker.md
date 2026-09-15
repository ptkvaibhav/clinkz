# Write crossing cannot fire on an authenticated SPA

**Report only, 2026-09-10, tree at `b45b239`. The constraint on the next
capability round, named before it is scoped.**

The run facts this is about (cal.diy, from the PR #141 measurement): **46
endpoints, every one `GET`, `has_form=0`, the deterministic bucket for
`_test_write_crossing` empty.** Nothing below re-derives those numbers; what it
does is establish, from the code, exactly which line refuses and what would
have to change for it not to.

---

## 1 · The refusal is one line

`agents/exploit.py::_applicable_methods_for_endpoint`:

```python
if endpoint.has_form or (endpoint.method or "GET").upper() in ("POST", "PUT", "PATCH"):
    methods += ["_test_input_validation", "_test_mass_assignment"]
    if len(self._principals) >= 2:
        methods.append("_test_write_crossing")
```

`_applicable_methods_for_endpoint` is the **only** producer of the deterministic
Tier-1 buckets (`_build_deterministic_tasks` iterates
`for method_name in self._applicable_methods_for_endpoint(ep)`). A class absent
from every endpoint's list has an empty bucket, is absent from the interleave,
and never reaches the class floor — `_CLASS_FLOOR_TASKS` reserves the top 3 of a
bucket that does not exist.

So on cal.diy the class is not truncated, not out-ranked and not abstaining.
**It is never planned.** Its own preconditions — a write locatable in a separate
read, records that name an owner, `ref(B)` discovered by probing as B — are
never consulted, because nothing gets far enough to consult them.

Note what this is **not**: `_CLASS_PRECONDITIONS["_test_write_crossing"] =
("form",)` and `_endpoint_meets_precondition` are a **ranking** signal, not a
gate. On an all-GET crawl they cost the class grade 0 and sort it last. That
would be survivable. The queue gate above is not.

---

## 2 · What the scan phase would have to produce

An `Endpoint` with `method ∈ {POST, PUT, PATCH}` **or** `has_form=True`. There
are exactly five producers that can set either, and each fails on this target
shape for its own reason:

| # | producer | how it learns a write | why it produced nothing here |
|---|---|---|---|
| 1 | HTML crawl → `has_form` | parses `<form>` out of a served document | an SPA ships no `<form>` in server-rendered HTML. **Structurally dead**, not a bug |
| 2 | `OpenAPIDiscoverer` | `method=method.upper()` per spec operation | cal.com serves no spec at a conventional path; the discoverer probes conventions only |
| 3 | `JSCallSiteDiscoverer` | `method=site.method.upper()`, read from the bundle's own `fetch`/`axios` call sites | **the live route** — see §3 |
| 4 | `GraphQLDiscoverer` | hardcodes `method="POST"` per introspected mutation | needs introspection enabled |
| 5 | `_api_schema.learn_allowed_methods` | `OPTIONS` per route, reads the **`Allow`** header | the target must answer `OPTIONS` with `Allow:` naming a write verb |

`StaticBundleDiscoverer` — the one that produced the 46 — is not on the list.
It emits `Endpoint(url=url, method="GET", params=params)` with `method` a
**literal**. It mines URL string literals out of JS, and a URL literal carries
no method. Its output is all-GET by construction, on every target, and always
will be. **That is where the 46 came from and why they are all GET.** No fix
belongs there.

Producer 5 deserves a note, because it is the one already built for exactly
this problem — its docstring says so: *"the write verbs the target says it
accepts, which is how a `PUT`/`PATCH` injection point becomes reachable at all
when the frontend only ever calls `GET`."* It reads `Allow` and deliberately
**not** `Access-Control-Allow-Methods` (reading the CORS header once
manufactured 105 endpoints from one wildcard). So it is sound and it is
target-dependent: a framework that answers `OPTIONS` without `Allow` hands it
nothing. **The first thing the next round should measure is whether the sweep
ran at all on cal.diy** — `_learn_api_schemas` returns early on
`self._budget_exhausted()`, and `MAX_OPTIONS_PROBES = 40` against a 46-endpoint
crawl is a live constraint on its own. That is a falsifiable prediction, cheap
to check in the trace.

> **MEASURED, 2026-09-12 — see [`options-sweep-measurement.md`](options-sweep-measurement.md).**
> It ran (197 s scan against a 900 s budget; the sweep costs 0.11 s), and it was
> not checkable *in the trace* — a local-mode run writes no `tool_invocations/`,
> so it had to be re-run live. **All 44 routes answered and not one named a write
> verb**: 40 said `Allow: HEAD`, one said `GET, HEAD, OPTIONS`, and the three
> that matter (`/`, `/api/book/event`, `/api/trpc`) returned no `Allow` at all.
> Producer 5 is sound and **exhausted on production Next.js**. The work moves to
> producer 3, as §5.3 anticipated.

### And §6's law is in this path too

`agents/_js_api_mining.py::_call_site_from_args`:

```python
if method is None:
    method = "GET"
```

A call site whose method the miner could not read becomes a GET endpoint,
**byte-identical to one it read as GET**. This is the default-control law in the
discovery layer: the absence is spelled as a measurement. It matters more here
than in most places, because `GET` is precisely the value that removes the
endpoint from all seven classes in §4. cal.com's writes go through tRPC, where
the method lives in the link configuration and not at the call site — so this
branch is not a corner case on this target, it is the common path.

The honest form is a third state: a call site with an unread method is not a
GET, and an endpoint the miner is unsure about should say so rather than be
counted as read. Same shape as invariant 101.

---

## 3 · Does a seated session help? Yes to reach, no to method

The session **is** carried, and the wiring is right:

* `ScanAgent._discovery_http_get` attaches `self._session_cookies` and
  `self._session_headers` (cookies *and* the bearer) to every discovery fetch,
  and `RouteDiscoverer`'s protocol docstring already promises this: *"all
  network access goes through the injected `FetchFn`, which carries the
  engagement session."*
* The crawl itself is session-bearing (`_build_tool_input` attaches the cookie
  header), and discovery is seeded from **every crawled page**
  (`_discovery_page_seeds`), not just the origin root.
* Phase order is on our side: authentication runs **before** scan.

So an authenticated shell document is fetched, its authenticated
`<script src>` chunks are fetched, and their call sites are mined. Routes that
were invisible anonymously do become visible. **That half works.**

What a session does not do is make an *unreadable method* readable. Three
bounds, and none of them is authentication:

1. **`_MAX_BUNDLES = 12`** per discoverer, `_MAX_DISCOVERY_PAGES = 25` seeds,
   `_MAX_BUNDLE_BYTES = 6 MB`. cal.com serves ~31 chunks; the earlier
   measurement recorded 8 fetched. The chunk carrying an authenticated write
   call site is as likely to be outside the budget as inside it, and which 12
   are taken is queue order, not relevance. `JSCallSiteDiscoverer` and
   `StaticBundleDiscoverer` each hold their own 12 (`visited` is per-`discover`
   call); `_MemoFetch` shares the *fetches*, not the *caps*.
2. **The probe is `GET`-only, correctly.** `_discovery_http_get` hardcodes
   `"method": "GET"`, and `_safe_method_probe` refuses anything outside
   `GET`/`HEAD`/`OPTIONS` and says why: *"this is the seam where a schema
   learner could otherwise turn surface mapping into a write"* (invariant 21).
   Nothing in the next round should touch that.
3. **The GET fallback in §2 above** erases the difference between a read method
   and an unread one.

**So the session moves the boundary from "cannot see the page" to "can see the
page, cannot see the verb", and the verb is the half the gate reads.** An
authenticated re-run alone will not enter the class; it will produce more GET
endpoints.

---

## 4 · Which classes share this exact blocker

Computed from `_applicable_methods_for_endpoint` (the set of `_test_*` string
literals it names) against `TIER1_TESTS`, not hand-listed.

### Hard-blocked — the write gate is their only route in (4)

| class | queued by |
|---|---|
| `_test_xss_stored` | `method ∈ {POST,PUT,PATCH}` — nothing else |
| `_test_input_validation` | `has_form or method ∈ {POST,PUT,PATCH}` |
| `_test_mass_assignment` | `has_form or method ∈ {POST,PUT,PATCH}` |
| `_test_write_crossing` | the same, **plus** `len(self._principals) >= 2` |

### Never deterministically queued at all — a worse condition (3)

`TIER1_TESTS − {classes named in the gate}` is exactly:

* `_test_state_sequence`
* `_test_constraint_violation`
* `_test_repeatability`

These three carry `("form",)` in `_CLASS_PRECONDITIONS`, so they are ranked as
if they had a bucket, and `_applicable_methods_for_endpoint` never names them.
On **any** target, on an SPA or not, they reach the plan only when the LLM
planner happens to name their endpoint. That is a separate defect from the SPA
blocker and it is worth registering on its own — it is invariant 51's shape
(*every applicable class is guaranteed one task before the cap*) evaluated
against a class the coverage pass does not consider applicable anywhere.

### Degraded but not dead — a path-name escape hatch (3)

| class | second route in | what the escape costs |
|---|---|---|
| `_test_csrf` | `_CLASS_PATH_TOKENS["_test_csrf"]` matches the path | a path-name guess, on an SPA whose routes are client-side |
| `_test_file_upload` | `"upload" in path` | same |
| `_test_brute_force` | `_AUTH_PARAM_NAMES` or `_LOGIN_PATH_HINTS` | reliable here — the auth layer finds the login endpoint independently |

**Seven share the blocker (4 hard + 3 with no deterministic route at all), three
more are degraded to a path-name guess.** The brief estimated six; the computed
answer is seven, and the extra one is `_test_xss_stored`, which is easy to miss
because it is the only injection-family class in the group.

### And a thirteenth-class ranking effect, separately

`_CLASS_PRECONDITIONS` gives `form` to **13** classes
(`_test_brute_force`, `_test_constraint_violation`, `_test_crypto`,
`_test_csrf`, `_test_file_upload`, `_test_input_validation`,
`_test_javascript_attacks`, `_test_mass_assignment`, `_test_repeatability`,
`_test_state_sequence`, `_test_weak_session`, `_test_write_crossing`,
`_test_xss_stored`). `_endpoint_meets_precondition("form", …)` is
`endpoint.has_form or method in (POST, PUT, PATCH)` — the same predicate as the
gate. On an all-GET crawl **all 13 lose grade 0** and sort behind any class with
a parameter match. Two of them (`_test_crypto`, `_test_weak_session`) survive on
`sets_cookie`, which an authenticated SPA does set.

---

## 5 · The shape of the next round, named

Not scoped here, deliberately. What the constraint says about it:

1. **The blocker is a discovery-layer problem, not a methodology one.** Every
   precondition `_test_write_crossing` declares is downstream of a queue gate
   that never fires. Building more oracle is building on a road that does not
   reach.
2. ~~**The cheapest measurement first**: did the `OPTIONS` sweep run on
   cal.diy, and what did the target answer?~~ **Done** —
   [`options-sweep-measurement.md`](options-sweep-measurement.md). It ran and
   the target names no write verb on any of the 44 routes, so **the work moves
   to producer 3**, exactly as the conditional here said it would.
3. **Producer 3 has two independent defects** and they need separating: bundle
   *coverage* (12 of ~31) and method *readability* (the `GET` fallback, plus
   tRPC/server-action shapes the miner has no pattern for). The second is the
   §6 law and is the smaller change.

   > **DONE for readability, 2026-09-15 — and the live measurement says the
   > prediction was wrong about which defect binds.** See §6.

4. **Do not relax the write gate to admit GET endpoints.** A GET endpoint
   admitted to `_test_write_crossing` is a terminal, mutating class dispatched
   against a route with no evidence it writes — invariant 88 plus a residual
   mutation in another principal's data. The gate is right; the input to it is
   what is missing.
5. **`_test_state_sequence` / `_test_constraint_violation` /
   `_test_repeatability` are a separate ticket.** They are not SPA-blocked; they
   are unqueued everywhere.


---

## 6 · Producer 3, the readability half — built, and what it measured

**Tree at `feat/xss-evidence-gate`, 2026-09-15. Live against the local
`caldiy-calcom-1` and `clinkz-juiceshop` containers, read-only GETs.**

### What was built

`_call_site_from_args`'s `if method is None: method = "GET"` is gone, replaced by
three states on `ApiCallSite` and on `Endpoint`
(`models/scan.py::MethodEvidence`):

| value | meaning | example |
|---|---|---|
| `NAMED` | the source or the protocol stated the verb | `.post(`, `{method:"PUT"}`, `open("POST",…)`, an `Allow` header, `<form method>`, an OpenAPI operation |
| `PLATFORM_DEFAULT` | no verb was named and **none could have been** — the idiom's own default IS the verb | a bare `fetch(url)`, an init object read in full with no `method` key, a crawled link |
| `UNREAD` | a config argument exists that we cannot see into | `fetch(u, cfg)`, `{...spread}`, `{method: z.k}` |

Three consequences, none of which relaxes §5.4's rule:

* **`UNREAD` never admits an endpoint to a write class.** Pinned
  (`test_an_unread_verb_never_admits_an_endpoint_to_a_write_class`), because the
  tempting next step after adding the state is to let it into the gate, and a
  terminal mutating class against a route with no evidence it writes is
  invariant 88 plus a residual mutation in another principal's data.
* **The `OPTIONS` sweep asks an unread route first — within its relevance
  grade.** Across grades it would undo the 32-of-40 ordering fix, because every
  bundle is unread by construction.
* **It is disclosed** (`MethodProvenance` → `report.method_provenance`), on a
  clean run too: *"every one of the N discovered endpoints carries a method the
  engine READ"* is the claim that makes an all-GET surface a statement about the
  target rather than about us.

And one capability gain that is not about honesty at all: `{method: m}` where `m`
is a local binding now RESOLVES. A bundler that hoists the verb into a local was
producing a `GET` endpoint from a write call site — not an absence, a read the
miner declined to make.

### What the live measurement says

| | cal.com | Juice Shop |
|---|---|---|
| distinct `<script src>` across 3 pages | 44 | 6 |
| distinct chunk URLs seen | 53 | 26 |
| bundles read (`_MAX_BUNDLES = 12`) | 12 | 12 |
| **still queued when the cap bound** | **41** | **14** |
| call sites mined | 2 | 87 |
| `named` / `platform_default` / `unread` | 1 / 1 / **0** | 87 / 0 / **0** |
| write verbs mined | 0 | **40** (23 POST, 12 PUT, 4 DELETE, 1 PATCH) |

**The third state does not fire on either target, and that is the finding.** On
Juice Shop the Angular idiom is fully readable — all 87 verbs named, 40 of them
writes — so the disclosure correctly reports a surface whose verbs were all read.
On cal.com it does not fire for a different and more useful reason: the 7
call sites whose config the miner cannot see into are dropped **one step
earlier**, at URL resolution. Measured individually: of the unreadable-init
sites, **2 of 2 also had an unresolvable URL** (the first argument is a bare
minified identifier, `fetch(e, n)`), and the other 2 are `.request(cfg)` /
`.ajax(cfg)`, where the config is argument **0** and the miner looks for a URL
there.

So §5.3's split was right that there are two defects and wrong about which one
binds on this target. The readability half is built and correct and it changes
nothing on cal.com, because:

1. **Bundle coverage is the hard bound**: 12 read, **41 still queued**. Not "8 of
   31" — seeding from three pages surfaces 53 chunk URLs, and the cap binds by a
   factor of four.
2. **URL resolution, not method resolution, is what drops cal.com's write call
   sites.** `_resolve_url_expression` on a bare identifier returns nothing, so
   there is no call site for a method to be unread ON.
3. `.request(cfg)` / `.ajax(cfg)` / `axios(cfg)` put the URL inside the config
   object, and `_call_site_from_args` treats argument 0 as the URL. Those shapes
   yield no endpoint at all on any target.

### What the next round should take, in order

1. **The config-object call form** (`axios(cfg)`, `.request(cfg)`, `.ajax(cfg)`
   and `fetch(cfg)`) — read the URL out of argument 0's `url` key, the way the
   `axios({url:…})` branch already does for `axios`. Smallest change, and it is
   the one that makes the other two matter.
2. **Bundle coverage.** `_MAX_BUNDLES = 12` against 53, taken in queue order —
   invariant 106's law with no ordering signal available, because
   `crawl_visit_priority` grades every `.js` chunk **2** and cannot separate
   them. So this is not "raise the cap": it needs a signal, and the honest
   interim is the disclosure (a bundle-budget truncation record beside the probe
   one). Do not raise the cap silently.
3. **Identifier URL resolution across a module boundary.** `_resolve_binding`
   searches backwards within `_BINDING_LOOKBACK = 20,000` characters of the call;
   a webpack chunk defines the base in another module entirely. This is the
   expensive one and it should be scoped only after 1 and 2.
