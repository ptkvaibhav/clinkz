# P6 — out-of-band confirmation: live isolation validation

> **Raw artifacts:** the `outputs/…` run artifacts cited below are local-only by policy — retained by the operator, not committed to the repo.

Raw writeup of the P6 build against `docs/p6-oob-design.md`. Scope is the design's
**isolation-first** cut (§P6.6): build the *collaborator + P6 confirmation* and
validate them on a **known-real SSRF we already confirm in-band** — one new variable
(the OOB confirmation), ground-truth check. **NOT Log4Shell** (deferred — it needs
the unbuilt log-sink reachability co-requisite, §P6.5.3).

Driver: [`scripts/live_oob_ssrf_validation.py`](../scripts/live_oob_ssrf_validation.py).
Real run vs a **live GeoServer 2.19.1** (Vulhub `geoserver/CVE-2021-40822`, :8080)
and a **live collaborator**, with a **live Anthropic exploit LLM** in the in-band
ranking loop — no harness, no silent-LLM stand-in (lessons #18/#28). Raw artifacts
under [`outputs/p6-oob-ssrf/`](../outputs/p6-oob-ssrf/) (`report.json`,
`trace.jsonl`, `live_run_stdout.log`), engagement `0b993c1e`.

---

## What P6 is

A blind capability is confirmed when an **inbound callback bearing a Clinkz-minted,
single-use nonce** reaches a Clinkz-owned collaborator within a wait window. It is
**zero-FP by construction** (§P6.2.2): the nonce is minted at dispatch and embedded
*only* in the one outbound probe, so a packet bearing it can only exist if something
that received the probe **executed the egress capability**. There is no reflection
channel to the collaborator, so the input-reflection confounder that every in-band
guard exists to defeat is *structurally absent*.

## What the class required (the honest metric)

| Piece | Where | Note |
|---|---|---|
| The structural exfil guardrail | `oob/templates.py` | CLINKZ-OWNED templates + a carrier that interpolates ONLY a validated `[a-z0-9]` nonce; **no parameter** for target data. §P6.7.4. |
| The receive-only collaborator | `oob/collaborator.py` | DNS (UDP) + HTTP listener, bounded+redacted log, nonce→hypothesis correlation, self-round-trip health-check, fire-and-reap reaper. |
| SSRF blind branch un-pruned | `exploit.py::_ssrf_oob_*` | `_ssrf_oob_confirm_batch` (fire-and-reap) / `_ssrf_oob_confirm` (single-shot) / `_ssrf_oob_send` / `_build_oob_confirmation_evidence`. **Zero new confirmation logic** beyond one helper. |
| Model + config | `models/methodology.py`, `config.py` | `ConfirmationEvidence.outbound_probe`, `SSRFExploitationType.BLIND_OOB_CONFIRMED`, the `OOB_*` knobs (disabled by default). |
| Orchestrator provisioning | `orchestrator.py`, `lifecycle.py` | `_provision_collaborator` (health-check gate) + teardown; wired onto the Exploit agent. |

`ConfirmationEvidence`'s **third consumer** after SSRF-P3 and file-read-P3 — the
general shape held again.

---

## The structural exfil guardrail (§P6.7.4 — the load-bearing safety property)

The design's open safety question: an OOB channel *could* become an exfil channel if
a careless payload encoded target data into the callback host. The resolution is
**structural, not convention**:

- OOB payloads are built **only** from CLINKZ-OWNED per-class templates
  (`OOBTemplateId`). The methodology/LLM *selects* a template — it **never authors**
  the payload string.
- `build_oob_payload()` has **no parameter** through which target/LLM/source data
  could ride (its only inputs are a template id, a nonce, a zone, a shape), and it
  **rejects** any nonce that is not `[a-z0-9]{16,64}` and any zone that is not a bare
  host/`host:port`. So `${env:AWS_SECRET}.<nonce>`, a subdomain-encoded file byte,
  `../etc/passwd`, or a target hostname are **not payloads the carrier can be asked
  to build** — the interpolation slot for arbitrary data does not exist.

Live run, section D — every exfil attempt is refused, and a real nonce produces a
fixed-host callback:

```
D. EXFIL GUARDRAIL — the carrier refuses to build an exfil payload
  refused exfil attempt '${env:AWS_SECRET_ACCESS_KEY}' (ValueError) ✓
  refused exfil attempt '../../etc/passwd' (ValueError) ✓
  refused exfil attempt 'victim.internal' (ValueError) ✓
  refused exfil attempt 'a b' (ValueError) ✓
  carrier output for a real nonce: http://host.docker.internal:18080/obmswj3jgfviq7gqlrskrs3aym
```

Locked in by `tests/test_oob/test_templates.py` (incl. an assertion that the carrier
signature has *no* target-data parameter).

---

## The four raw proofs

### A. In-band SSRF unregressed (P3)

The same GeoServer SSRF still confirms in-band — P6 is **added**, not at the expense
of the built primitive:

```
[HIGH] Server-Side Request Forgery (SSRF) — reflected_internal   status=confirmed
  Response: loopback fetch reflected in-scope internal content ('GeoServer: Redirecting')
            via http://127.0.0.1:8080/geoserver/ (status 200)
  capability=fetch_confirmed=True,content_reflected=True
```

### B. P6 confirm via the callback — RAW-AUDITABLE

Pointing the SSRF `url` at the collaborator, GeoServer executes the egress and a
callback bearing the probe's nonce arrives. The finding carries **both halves** of
the evidence pair (§P6.2.4) — the outbound probe carrying nonce `T` and the inbound
callback carrying the **same** `T`:

```
[HIGH] Server-Side Request Forgery (SSRF) — blind_oob_confirmed   status=confirmed
  capability=fetch_confirmed=True,content_reflected=False        ← genuinely blind
  strength=verified-oob
  outbound_probe: POST http://localhost:8080/geoserver/TestWfsPost
                  — url=http://host.docker.internal:18080/vkp2qthmfi65kpkl6mbwwe56wa
  callback_nonce='vkp2qthmfi65kpkl6mbwwe56wa' (carried only in the one outbound probe;
                  control_bore_it=False)
  confirming_excerpt: inbound callback: proto=http src=127.0.0.1
                  host=host.docker.internal:18080 path=/vkp2qthmfi65kpkl6mbwwe56wa
```

A reviewer re-derives the verdict with zero trust in Clinkz's assertion: `T` was
random, placed only in that one probe, and came back to the listener. (The callback
`src` is `127.0.0.1` because Docker Desktop's proxy NATs the container→host hop — the
**nonce is the hard proof**; the source IP is a soft corroborator, exactly as
§P6.2.2 states.)

### C. Zero-FP — egress denied → no callback → no finding

The **same** probe with the fetch guard's egress denied (the Host-alignment carrier
removed, so GeoServer rejects the cross-host fetch) produces no callback:

```
C. ZERO-FP — same probe, fetch-guard egress denied (no carrier) → no callback
  control confirmed_out_of_band=False
  note=blind_unconfirmed (egress may be filtered) — no callback within the window
```

No callback → no confirmation → no finding. And the honest inverse is preserved: a
non-confirmation is `blind_unconfirmed (egress may be filtered)` — an operator
research-lead, **never** `not_vulnerable`.

### D. Exfil guardrail — above.

**Verdict from raw:** `A ∧ B ∧ C ∧ D = PASS`.

---

## False-negative floor & the health-check gate (§P6.3.4 / §P6.7.1)

P6 buys zero false-positives at the cost of false-*negatives* under egress filtering:
a callback that never comes is **inconclusive, not safe**. So the outcomes are kept
distinct in `SSRFMethodologyResult`:

- callback → `BLIND_OOB_CONFIRMED` (a finding);
- healthy collaborator, no callback → `blind_unconfirmed (egress may be filtered)`
  (research-lead, never `not_vulnerable`);
- no healthy collaborator → `collaborator_unavailable` (a dead collaborator must
  **not** make a target look clean — surfaced as "collaborator unavailable", never
  `blind_unconfirmed`).

The collaborator's preflight **health-check** (mint a token, self-hit both DNS and
HTTP, confirm the round-trip) is the gate: only a *healthy* collaborator may turn a
non-confirmation into a research-lead. All three distinctions are unit-locked in
`tests/test_agents/test_methodology_ssrf_oob.py`.

---

## Reachability note (paper-vs-live divergence, documented)

The design's canonical callback shape is `<nonce>.<zone>` (subdomain), which needs
wildcard-DNS delegation the target actually queries. For the **docker-mode HTTP
leg** the build also supports the **PATH shape** (`http://<zone>/<nonce>`, §P6.1.1
explicitly allows the nonce in the HTTP path), which needs **no DNS delegation** and
is the strongest form of the guardrail (the callback host is a fixed authority with
no variable at all). The validation used the PATH shape with
`zone=host.docker.internal:18080`: the GeoServer container reaches the host
collaborator (an IPv4 `0.0.0.0` listener) directly — confirmed by a pre-run
reachability probe (`docker exec … curl host.docker.internal:18080` → the host
listener recorded it). The DNS leg is exercised by the collaborator's own
self-round-trip health-check. Log4Shell's DNS-only egress would use the subdomain
shape + the DNS leg — deferred with the log-sink channel.

## What was NOT changed (unregressed by construction + keyless-confirmed)

The file-read capability class (`_test_lfi` / `FILE_READ` catalog / the P3 file-read
oracle) is **untouched** by this PR. The keyless gate — **1456 passed** — includes
`test_flink_file_read`, `test_methodology_lfi`, `test_solr_transfer`, and the whole
SSRF/discovery family, so in-band SSRF and file read are confirmed unregressed. The
`JNDI_LDAP` / `DNS_LOOKUP` templates exist for carrier genericity but are **not wired
to a methodology** this build (Log4Shell deferred).
