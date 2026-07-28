# SSRF — `_test_ssrf`

Second Tier-2 primitive. Coerce the in-scope server to fetch internal/metadata
addresses. **Parameter-scoped** like SSTI (runs per URL/fetch param) and reuses
the shared string-only `_send_probe` — the internal URL is just a string param
*value*, so **no dedicated carrier**. Models in `models/methodology.py`
(`SSRFExploitationType`, `SSRFCapability`, `SSRFMethodologyResult`).

## Safety model — the load-bearing scope interaction

Clinkz only ever connects to the in-scope target; the internal address rides as
the param *value* in a request to that target, and the scope-validated HTTP
client checks the *request URL* (the in-scope host via `urlparse` — an internal
address embedded in a query/body value is never the netloc), so
`scope.contains("http://target/x?url=http://169.254.169.254/")` is **allowed**
while `scope.contains("http://169.254.169.254/")` is **blocked**;
`follow_redirects` defaults False so a 3xx the target returns to an internal
address is never followed. There is deliberately **no `_xxe_payload_in_scope`-style
restriction** on the payload — pointing at internal/metadata addresses is the
whole test.

## Phases

- **Phase 1** maps the injection point: a URL-shaped name (`_SSRF_PARAM_NAMES`)/
  value, or a server-side-fetch signal — supplying the in-scope origin vs a
  non-resolving `.invalid` control (both as param values) and observing a
  divergence the **value-echo cannot explain** (`_ssrf_fetch_signal` strips the
  injected value before the length compare, so a plain reflecting field like
  DVWA's `name` is not mistaken for a fetcher).
- **Phase 2** fingerprints `SSRFCapability` — `fetch_confirmed`,
  `content_reflected` (**the in-band gate**: the fetched body echoed back),
  network schemes only. **`file://` is NOT an SSRF type** — a local-file read is
  LFI (handled by `_test_lfi`); SSRF no longer probes `file://` (this removed the
  `/fi/?page=file:///etc/passwd` mislabel).
- **Phase 3** ranks in-band types (LLM checkpoint, Anthropic-pinned) — but **with
  no content reflection the only outcome is `BLIND_DEFERRED`** (no LLM call).
- **Phase 4** synthesis is **deterministic** and bounded to fixed well-known
  internal/metadata targets (`169.254.169.254`/`metadata.google.internal`/
  `100.100.100.100`, `127.0.0.1:<port>` loopback) — **never an arbitrary external
  exfil host**.
- **Phase 5 is in-band only**: confirmed when the response reflects internal
  content it should not have — a cloud-metadata signature
  (`_SSRF_METADATA_SIGNATURES`), or the app's own loopback content. **Reflection-
  honest** like CMDi/SSTI: the signature tokens are response-content the metadata
  service returns (`ami-id`, `AccessKeyId`), never substrings of the URL we sent;
  and IAM exposure reports only the field name, never the secret value
  (`_ssrf_signature_match`). Severity **critical** (cloud-metadata / IAM exposure)
  / **high** (internal-service).

## A failed fetch is reachability, not disclosure (gap G12, engagement `cb54495c`)

The run confirmed a **HIGH** "Server-Side Request Forgery (SSRF) — internal_service"
on a loopback fetch whose reflected "internal content" was the string
`'403 Forbidden'`:

```
Response: loopback fetch reflected in-scope internal content ('403 Forbidden')
confirming_excerpt: <b>Warning</b>: include(http://127.0.0.1:80/vulnerabilities/):
  Failed to open stream: HTTP request failed! HTTP/1.1 403 Forbidden
```

**Root cause.** `_ssrf_marker_at_path` harvested the marker from a reference page
that itself answered **403**, so the "distinctive marker" *was* the HTTP status
line — the very string the fetching stack prints in its own failure message.
Matching it could not distinguish *the app returned me the internal resource*
from *the app told me the fetch failed*, and the non-resolving control could not
either (that control only proves a request went out, which it did).

**Position.** The fetch is real: a server-side request was issued to an internal
address and distinguished from a control, so **reachability is proven**. But the
defining effect of SSRF is *internal content the application should not return*,
and a 403 error page is not that — nothing was disclosed. So it is not a
high-severity SSRF finding, and it is not nothing either.

**Three fixes, all general:**

1. A marker is only harvested from a **2xx** reference. A non-2xx reference served
   an error page, and an error page's chrome is not internal content.
2. HTTP status boilerplate is rejected as a marker outright
   (`_SSRF_BOILERPLATE_MARKER_RE`) — a `<title>` of `403 Forbidden` /
   `404 Not Found` / `Internal Server Error` proves nothing wherever it came from.
3. A marker appearing **only** inside a fetch-failure message
   (`_FETCH_FAILURE_MARKERS`) does not confirm; the candidate falls through to the
   blind branch.

**Where the observation goes.** A proven fetch that discloses nothing is now
recorded by `_record_ssrf_reach_lead` as an `UnprovenExploitLead`
(`blind_unconfirmed_within_window` when P6 was sent and no callback landed,
`not_instrumentable` when no collaborator was wired). The reachability survives
for the operator; the exploitation claim does not. P6 still promotes it to a
finding when a callback lands.

## Blind SSRF — confirmed out-of-band (P6) when a collaborator is wired, else deferred

A confirmed fetch with no in-band reflection is no longer a dead end. When a
**healthy** OOB collaborator is provisioned (`OOB_COLLABORATOR_MODE != disabled`;
see [out-of-band-p6](out-of-band-p6.md)), `_test_ssrf` fires the blind set through
`_ssrf_oob_confirm_batch` (fire-and-reap, one shared window) and confirms on a
callback bearing the probe's nonce (`BLIND_OOB_CONFIRMED`, high, raw-auditable).
With no callback the outcome is `blind_unconfirmed (egress may be filtered)` — an
operator research-lead, never `not_vulnerable`; with no healthy collaborator it is
`collaborator_unavailable` (never `blind_unconfirmed` — a dead collaborator must
not make a target look clean). With P6 **disabled** (the default) it emits NOTHING
and notes `blind_suspected` — the unchanged black-box floor, never a phantom.

**Juice Shop's canonical surface (`POST /profile/image/url`, `imageUrl`) is blind
by design** — it pipes the fetched body to a file and 302-redirects, so the
`juiceshop_smoke` gate is skip-tolerant: a justified blind-deferred non-finding
unless a build reflects in-band OR a collaborator confirms out-of-band (in-band
six-phase path unit-proven in `test_methodology_ssrf`; OOB path in
`test_methodology_ssrf_oob`). N/A by construction on DVWA (no URL/fetch param
surface).
