# Discovery engine — slice 1 validation (GeoServer CVE-2021-40822)

> **Raw artifacts:** the `outputs/…` run artifacts cited below are local-only by policy — retained by the operator, not committed to the repo.

**Status:** live-validated, PASS.
**Scope:** the FIRST vertical slice of the discovery engine (`docs/discovery-engine-design.md`) —
a thin end-to-end path for ONE real CVE, deliberately concrete-first so the abstractions are
tested against a live target before any generalization. This is **not** the general engine (no
full capability catalog, no general reachability, no wired agents).

The single most valuable output of this slice is not the passing run — it is the honest account
of **where the paper design diverged from what the live run actually needed**. That account is the
bulk of this document (§4).

---

## 1. What was built

Three layers, one commit each, over ONE fixture (`tests/fixtures/geoserver_TestWfsPost.java`, real
GeoServer 2.19.1 source):

| Layer | Commit | Module | What it does for this slice |
|---|---|---|---|
| Source ingestion (§2.2) | `a958962` | `discovery/source_ingest.py` | Bounded regex ingest of the Java servlet → `SourceModel`: the `TestWfsPost` entrypoint, the intra-function `url → new URL() → openConnection()` taint path (@173), and the `validateURL` host-check guard (@375) with its operands classified attacker- vs config-controlled. |
| Capability × Intent × Reachability | `c6e617e` | `discovery/{catalog,intent,reachability,hypothesis,engine}.py` | One payload-free `EGRESS_FETCH` primitive whose proof obligation reduces to **built** confirmation primitives (P3/P1); Δ adjudication; intra-function reachability edge; a Tier-A `_test_ssrf` hypothesis carrying a per-instance carrier constraint. |
| Proof seam (§2.7) | `9d5e298` | `agents/exploit.py` | Hypothesis lowers to an `ExploitTask`, unioned into the exploit plan as a **third source** (`_merge_discovery_tasks`) and dispatched through the unchanged proof engine. Adds the `align_host` carrier + the oracle fix (§4.1). |

**Confirmation reduces to a built primitive** (the zero-FP boundary the design mandates): the SSRF is
confirmed **in-band via P3** (internal content the payload never contained — GeoServer's own
`GeoServer: Redirecting` mount-base body), gated on a differential `.invalid` control. No OOB.

## 2. The live run (raw evidence)

Driver: `scripts/live_geoserver_discovery.py`, against live Vulhub `geoserver/CVE-2021-40822` on
`:8080`, with a **live Anthropic exploit LLM** (the methodology LLM is never stubbed — lessons
#18/#28). Latest passing engagement `14ca7001-944d-429a-89fc-216e609c000d`
(`outputs/14ca7001…/report_14ca7001….{json,md}`, `trace.jsonl`).

```
1. SOURCE INGESTION → entrypoint ['GET','POST'] /TestWfsPost params=['body','url','username','password']
                       call-site egress_fetch openConnection() tainted_by='url' guard=validateURL @173
                       guard validateURL kind=host_match bypassable=True gating=ProxyBaseUrl
   black-box: '/geoserver/TestWfsPost' linked from /geoserver/web/? False   ← gap #1 (unlinked demo servlet)
2. Δ: exposed conf=0.9 :: guard compares two attacker-controlled values, gated on ProxyBaseUrl (unset)
   reach: static_confirmed conf=0.9 :: url → new URL(...) → openConnection()
   → ExploitTask _test_ssrf POST …/TestWfsPost params=['url'] carrier=['align_host_with_injected_url_host']
3. PROOF: 46 tests run, 1 finding. [HIGH] SSRF — internal_service status=confirmed
          content_reflected=True via http://127.0.0.1:8080/geoserver/ (P3)
          confirming_excerpt: …<title>GeoServer: Redirecting</title>…  (fetched mount-base — marker present)
          control (WITHOUT carrier): <servlet-exception> java.lang.IllegalStateException…  (marker absent)
4. CARRIER: WITH → reflects 'GeoServer'; WITHOUT → IllegalStateException (host mismatch)   ← gap #3, now in-trace
5. ZERO-FP: control param 'username' → 0 SSRF findings

VERDICT: SSRF confirmed in-band (P3) ✔  carrier load-bearing ✔  zero false positives ✔  → PASS
```

## 3. What the paper got right (held under live fire)

- **Gap #1 (channel enumeration).** Source ingestion surfaced `/TestWfsPost`, which is genuinely
  **not linked** from the crawlable `/geoserver/web/` surface — a black-box crawl never reaches it.
  The gray-box value-add is real and observed, not hypothetical.
- **Gap #2 / open-question #7 (Δ under-count).** The design's insistence that the default
  `url.getHost() == requestUrl.getHost()` check is **not a real guard** (both operands
  attacker-controlled; the genuine guard is gated on `ProxyBaseUrl`, unset by default) held exactly.
  Intent scored it `EXPOSED` (conf 0.9), not `SANCTIONED`. A guard that fixes an operand still drops
  to no-Δ. The adjudication-is-a-decision framing was correct.
- **The proof-seam shape (§2.7).** Discovery as a *third* `ExploitTask` source, unioned at plan level
  and dispatched/deduped identically, required **zero** changes to dispatch, dedup, or persistence.
  The seam is inert by default (`_discovery_tasks` empty). This composed cleanly.
- **Reduction to a built primitive.** A hypothesis binding to the existing `_test_ssrf` inherited its
  zero-FP boundary — the control param produced no finding with no extra work.

## 4. Where the paper diverged from what the live run needed

This is the deliverable. Four divergences, ranked by how much they change the design's assumptions.

### 4.1 The confirmation ORACLE is target-shape-sensitive — the paper did NOT predict this (headline)

The design (§2.7) treats the existing proof engine as a **fixed black box**: "reuse the proven proof
engine, zero new proof code." The live run falsified the "zero new proof code" half.

The existing `_test_ssrf` in-band oracle reflected the **origin ROOT** marker and pointed its
internal probe at loopback **root** (`http://127.0.0.1:8080/`). GeoServer is mounted under a context
path (`/geoserver/`); its `/` is a **contentless 404 wrapped in a servlet-exception**. So the fetched
"internal content" was empty, `content_reflected` stayed **False**, and a genuinely exploitable SSRF
was mis-classified **BLIND** — a false negative on a CVE that is in fact in-band confirmable.

The fix (in `9d5e298`) is a real, if small, proof-engine change: reflect the app's **own mount base**
(first path segment of the page URL, e.g. `/geoserver/`) with a bounded redirect hop, and match each
loopback target to its own path's marker. Confirmation still reduces to P3 and the reflection guard is
intact — but the *oracle's notion of "internal content"* had to learn that apps live under context
paths, not at `/`.

**Why this matters for the general engine:** the paper's factorization
`Vuln = Δ-Capability × Reachability × Provable-Impact` implicitly assumes the third factor (the proof
engine) is complete and target-agnostic. It is not. The **confirmation oracle carries hidden
target-shape assumptions** (here: "the origin root serves identifying content"). Each new capability
the discovery engine reduces to a built primitive may surface a *fresh* oracle blind spot that only a
live run against that capability's real target shape will expose. The zero-FP boundary is sound; the
zero-*sensitivity* boundary (does the oracle even fire on a true positive?) is a separate axis the
design should name explicitly. **Recommendation:** treat "does the built primitive's oracle actually
fire on this target's true-positive shape?" as a first-class de-risking step for every future slice,
alongside the FP boundary.

### 4.2 The carrier constraint is real but *maskable* — the paper over-generalized its necessity

Gap #3 (align the request `Host` header with the injected url's host) was correctly predicted and IS
load-bearing. But the design implies it is *universally* necessary. Live showed a caveat: the SSRF
proof engine's internal-host set (`_SSRF_INTERNAL_HOSTS`) includes `localhost`. When the target is
addressed as `localhost:8080` and the loopback probe is *also* `localhost`, the `Host` header already
matches — the guard is satisfied **without** the carrier, so the carrier looks unnecessary.

The carrier's necessity is only *demonstrable* on a target addressed **differently** from the loopback
alias — `127.0.0.1`, `[::1]`, or a metadata IP. We isolate it there (§ live-run step 4):
`127.0.0.1` target → WITH carrier reflects GeoServer content; WITHOUT → `IllegalStateException`
(host mismatch). **Lesson:** a per-instance carrier constraint can be silently masked when the app's
own address coincides with an internal-host alias; validating "carrier is load-bearing" requires
choosing a probe target that does not self-align. The design should note that carrier necessity is a
property of the *(injected target, request Host)* pair, not of the vuln class.

### 4.3 The channel's HTML form action was a JavaScript sink, not a URL

The channel model (§2.2/§2.5) assumes an HTML `<form action=…>` names the fetch endpoint. TestWfsPost's
real form posts to `JavaScript:doNothing()` — a non-navigational sink. The generic `_send_probe` had to
learn to detect a non-`http(s)` form-action scheme and fall back to posting to the **endpoint URL** with
the `FORM_BODY` location, rather than "submitting the form" to a `javascript:` action. Small, but it
means **the crawled/parsed form action cannot be trusted as the request target** — the discovery
layer's `param_locations` (from source, not from the live form) is what carried the correct shape here.
A pure black-box channel model would have posted into the void.

### 4.4 Validation methodology: an isolated "control" must bypass the live form re-parse

Not an engine divergence, but a validation-honesty lesson worth recording. The first zero-FP control
attempt fetched the endpoint via `_fetch_page("username")` — which **re-parses the live TestWfsPost
HTML form** and re-adds the real `url` input to `input_params`. The methodology then (correctly) found
the genuine `url` SSRF, and the "control" showed 1 finding — a false INCOMPLETE that looked like an FP.
The fix constructs the control `PageAnalysis` directly with `input_params=["username"]` only. **Lesson:**
when isolating a single control parameter against a live page, do not route it through the form-parsing
fetch, or the page's real injectable inputs leak back into the control set. (The pipeline itself is
correct — it *should* find the real `url` param; the harness just wasn't isolating what it claimed to.)

### 4.5 Co-location instead of wired agents (sanctioned, not a surprise)

The engine (§2.1) is described as Orchestrator-wired agents. This slice co-locates all four layers into
one deterministic `DiscoveryEngine.discover()` pass. §2.1's co-location note anticipated exactly this as
the pragmatic first build, so it is a **sanctioned simplification**, not a surprise — but stated here for
completeness. Wiring discovery in as an Orchestrator-scheduled phase (populating `_discovery_tasks`
before the Exploit phase plans) is the next slice.

### 4.6 The confirmation was conclusion-only — now raw-auditable (validation-gap closure)

The first cut of this slice preserved the confirmation *conclusion* (`content_reflected=True`) but not the
*evidence*: the trace was exploit-phase events with no response bodies and no isolation, so a reviewer had to
**trust** that `GeoServer: Redirecting` came from the SSRF fetch rather than from TestWfsPost's own output. For a
zero-FP-moat product that is unacceptable — the FP boundary is only credible if a confirmation is independently
re-derivable from the artifact, not self-asserted.

Closed by persisting a bounded `ConfirmationEvidence` pair at confirm time (`models/methodology.py`;
`ExploitAgent._ssrf_internal_confirmation_evidence`), into **both** the finding evidence and the phase-5 trace
event: (a) the **confirming excerpt** — the raw reflected bytes anchored on the marker (`…<title>GeoServer:
Redirecting</title>…`, GeoServer's own mount-base redirect page proxied back), and (b) the **control** it was
distinguished against. For a carrier-bearing confirmation the control is the sharpest one — the *same*
internal-target probe re-sent WITHOUT the Host-alignment carrier, which the servlet rejects
(`java.lang.IllegalStateException`, marker absent). The pair makes "the marker is fetched content, not chrome"
visible in the raw bytes, and puts the §4.2 carrier isolation **inside the pipeline trace**, not only the driver's
stdout. Cloud-metadata excerpts redact credential values (a field name proves access, never the secret).

**Why this generalizes.** It is the operational form of the §4.1 lesson: reducing a capability to a "built,
proven" primitive is not enough — the confirmation must be *auditable*, so every discovery confirmation now
records the confirming-evidence-plus-control pair rather than a boolean. SSRF is the first consumer;
`ConfirmationEvidence` is the general shape. Re-validated live on engagement `14ca7001` (report + trace embed the
pair; the `username` control param still yields zero findings).

## 5. Net assessment

The factorization and the proof-seam shape held. The three §10 gaps were all real and all closed on a
live target. The one genuine surprise — worth more than the passing run — is **§4.1: reducing a
capability to a "built, proven" primitive does not guarantee the primitive's confirmation oracle fires
on the true positive.** The FP boundary is necessary but not sufficient; the next slices must de-risk
the *sensitivity* boundary per-capability, concretely, against the real target shape — exactly the
concrete-first discipline this slice was run under.

**Reproduce:** `python scripts/live_geoserver_discovery.py` (needs `ANTHROPIC_API_KEY` and live
GeoServer on `:8080`; STOPs with no substitute if either is absent). Deterministic parts are unit-gated
in `tests/test_discovery/` (source ingestion, engine chain, carrier + proof seam) — no key, no container.
