# File upload — `_test_file_upload`

Confirm on the stored artifact fetched back **executing** (a self-appended canary
echoed as interpreter output) — never on a filename echoed / form re-rendered /
merely retrievable.

## Acceptance + execution + multipart transport (LESSONS #27)

Both a real transport bug and an honesty gate. The methodology never genuinely
uploaded to DVWA — `_http_post_multipart` hardcoded the file field `name="file"`
(DVWA's input is `uploaded`), omitted the `Upload` submit field DVWA gates on, and
`http_client` sent the body via curl `-d` (strips CR/LF, corrupting multipart
framing) — so DVWA received no file at any level and just re-rendered the form,
whose `name="uploaded"` matched a bare `uploaded` success marker and emitted a
phantom "Unrestricted File Upload" at every level (the uniform-confirm-across-a-
graded-control phantom signature).

Fixes:

- **Transport** now threads the form's real file-field name + submit/hidden fields
  (`_upload_form_fields`) through `_http_post_multipart` and switches `http_client`
  to curl `--data-binary` so boundary CRLFs survive.
- **Acceptance** (`_upload_response_accepted`) anchors on a positive signal
  distinct from the form re-rendering — a boundary-anchored echo of the uploaded
  filename, an explicit success phrase, or a `Location` to the artifact (a bare
  form re-render is NOT accepted).
- **Phase 5 requires ground-truth execution** — the stored artifact fetched back
  must echo a self-appended canary as interpreter OUTPUT (`DIRECT_EXECUTION` and
  `INTERPRETER_MISCONFIG` alike; `INCLUSION_CHAIN`/`CLIENT_SIDE_ONLY` stay
  retrievability-grade documentation findings); a re-encoded/inert image or a
  source-served payload is a non-finding.

Low/medium confirm via real RCE; high (image-only, no direct exec) and impossible
(re-encode + token) emit nothing.

## The image carrier — asking the one remaining question (gap G5)

At the hardened DVWA levels phase-2 fingerprinting probed **only script
extensions** (`.php`, `.phtml`, `.asp`, …). A store that validates the real
extension rejects all of them, so `working_extensions` came back empty, every
ranked execution type declined, and the ladder stopped: **3 verifications / 0
emissions** at `medium`, **6 / 0** at `high` — even though the store was still
writable.

When no script extension works, phase 2 now asks the one question left: **will an
IMAGE extension carry a script body?** (`.jpg` / `.jpeg` / `.png` / `.gif` with a
`GIF89a` magic prefix and a script payload, recorded as
`FileUploadRestrictions.image_carrier_extension`). That is the upload half of an
inclusion chain — the carrier a hardened upload leaves open — and
`_fallback_file_upload_synthesis` uses it for `INCLUSION_CHAIN` when no script
extension is available. A store that accepts `.php` still wins; the carrier is
only probed when nothing else worked, so no extra requests are spent where the
answer is already known.

The confirmation oracle is unchanged: the artifact must still be fetched back and
observed executing (or, for the inclusion chain, be reachable through a consumer).
The carrier extends **reach**, not the definition of a confirmation.

## Accepted-by-the-store is not executed-by-the-server

Phase 2's `working_extensions` records which extensions the upload **accepted**;
only the server's handler mapping decides which ones **run**. On the DVWA image
Apache ships

```apache
<FilesMatch \.php$>
	SetHandler application/x-httpd-php
</FilesMatch>
```

so `.phtml` uploads fine and is then served as inert text (`Content-Type` empty,
body unchanged).

Phase-4 synthesis picks ONE extension, and at DVWA `low` the live model picked
`.phtml` on both upload tasks of engagement `ad62e582`: direct execution failed to
verify, and the CRITICAL finding its three predecessor runs emitted went missing —
on a payload choice, not on the target's posture. That is a contract violation, not
variance: a deterministic skill must find a present vuln every run, not when the
model guesses well.

`_file_upload_execution_candidates` therefore walks the confirmed set for
`direct_execution` — synthesis's pick first, then the remaining confirmed script
extensions in `_FILE_UPLOAD_EXEC_EXT_PREFERENCE` order, bounded at
`_FILE_UPLOAD_MAX_EXEC_ATTEMPTS` (3). The confirmed set is the empirically grounded
artifact; walking it is what makes the single pick stop mattering. The preference
order is only a heuristic — a target could filter `.php` at the handler while
running `.phtml`, which is exactly why the set is walked rather than reordered.

Every attempt is still decided by the **unchanged phase-5 execution oracle** (the
canary echoed without its source), and the canary is carried across attempts so the
oracle looks for one token. It adds **reach, never a new way to confirm**: with no
confirmed script extension the walk is just synthesis's pick, unchanged.

## A negative fingerprint can never confirm (G17, batch 5)

The batch-4 HIGH run emitted, as **confirmed/medium**:

```
File Upload Validation Gap (client_side_only)
verified=True strength=likely
restrictions={'working_extensions': [], 'content_type_check': False,
              'magic_byte_check': False, 'filename_injection_works': False}
```

Every probe that could have distinguished a gap came back negative, and the
finding was emitted for a `profile_pic.jpg` accepted exactly as DVWA `high` is
designed to accept it (it validates the real extension *and* the image
dimensions). The `rationale=` was a conditional execution claim — "will execute
only if the application later renders this uploaded 'image' inline in an HTML
context" — which is a shape that can never confirm.

Two independent gates now, both generic:

1. **`client_side_only` never verifies on retrievability.** Phase 5 returned
   `verified=True` on `fetch_resp.status == 200` alone for the branches with
   `requires_execution == False`. Accepted-and-retrievable is the upload feature
   working; client-side execution needs an oracle this engine does not have,
   which is the same gap that makes every DOM-XSS result a lead.
2. **No upload finding without a witnessed BYPASS** — `_file_upload_bypass_observed`:
   a script/interpreter extension the store accepted, or a filename injection
   that survived. Deliberately *not* positives: `content_type_check` and
   `magic_byte_check` record a defence the server was seen **enforcing**, and
   `image_carrier_extension` means the store takes images, which is the feature.
   Counting the carrier is what produced a finding on the one level whose upload
   control is doing its job.

The gate runs **before** the phase-3 LLM ranking, so which execution type the
model picks cannot decide whether the class may confirm — type selection is an
LLM checkpoint, and leaving "may this confirm?" downstream of it puts the honesty
decision in the model's hands (LESSONS #39).

The two surviving outcomes are both witnessed, and they witness different things:
`strength="verified"` is the canary echoing as interpreter output, and
`strength="verified-stored"` is a bypassed restriction plus a stored, retrievable
artifact — which is what an inclusion-chain finding actually claims. `"likely"`
is no longer assigned by this class at all.

**Per-level expectation.** LOW/MEDIUM accept `.php` under a declared image MIME →
`working_extensions` non-empty → the gate passes and DIRECT_EXECUTION confirms on
the canary. HIGH/IMPOSSIBLE reject every script extension and every filename
injection → the fingerprint is negative → the upload point is recorded as an
`UnprovenExploitLead` (`upload_accepted_but_no_restriction_bypass_observed`) and
**nothing is emitted**. That per-level split is the honesty control: a class that
confirmed identically at every level of a graded control was matching the app's
benign response.

## The family's confirmation model (G22, batch 6)

Three consecutive batches produced an unstable or over-claimed finding from three
*different* branches of this one methodology:

| batch | branch | what went wrong |
|---|---|---|
| 3 | `direct_execution` | one unlucky synthesis pick (`.phtml`) lost a CRITICAL that three prior runs found → the extension walk |
| 5 | `client_side_only` | verified on `status == 200` alone → the G17 phantom |
| 6 | `inclusion_chain` | present in 1 LOW run of 3, on the endpoint whose CRITICAL is stable in all 3 |

Three incidents in one family is a family-level defect, so the repair is one
rule rather than a third patch. Each execution type is a distinct **claim**, and
a claim is a finding only when the one observation that proves it was made
(`_FILE_UPLOAD_BRANCH_EFFECT`):

| branch | defining security effect | deterministic observation that proves it | engine has it? |
|---|---|---|---|
| `direct_execution` | the server executes attacker-supplied code from the stored artifact | the artifact fetched back echoes our canary as interpreter **output**, source absent | **yes** |
| `interpreter_misconfig` | a handler mapping runs the artifact through an interpreter under an atypical extension | the same canary-as-output oracle | **yes** |
| `inclusion_chain` | a **consumer sink** includes the stored artifact, so the upload half and the inclusion half compose into execution | the canary echoed as interpreter output when the artifact is reached **through that consumer**, distinguished from a direct fetch | **no** |
| `client_side_only` | a browser executes the stored content in the origin's security context | a client-side execution oracle | **no** |

Only the first two are in `_FILE_UPLOAD_CONFIRMABLE_TYPES`. The other two record
an `UnprovenExploitLead` carrying both halves — the effect claimed and the
observation missing — so the reachability is preserved and the claim is not.

### Why `inclusion_chain` was never a confirmation

Its verified branch was a bare `fetch_resp.status == 200` on a **direct GET** of
the artifact. Nothing in the engine invokes a consumer, and the agent keeps no
runtime record of a confirmed file-inclusion primitive to invoke one with
(`LFIMethodologyResult` is a local in `_test_lfi` and is dropped when it
returns) — so "the chain composes" was asserted by the finding's own title and
observed nowhere.

### Why that made the ranking decide the severity

Retrievability is trivially true **whenever direct execution would also have
worked**, and the phase-4/5 loop `break`s on the first branch that verifies. So
on the same upload point, a run whose model ranked `inclusion_chain` first
emitted a HIGH "validation gap" and **never attempted** the CRITICAL execution
finding. Which branch is tried first is an LLM checkpoint; whether a branch that
cannot prove its effect may pre-empt one that can is not (LESSONS #39). The
model's order is now preserved *within* each half and the confirmable half runs
first.

Two consequences fall out. `verified-stored` labelled exactly one thing — that
retrievability claim — so it leaves `_CONFIRMING_VERIFICATION_STRENGTHS` with
it. And `interpreter_misconfig` used to render `high` while `direct_execution`
rendered `critical` for byte-identical proof; both now grade on the effect they
proved, because which extension carried the execution is a detail of the route,
not of the impact.
