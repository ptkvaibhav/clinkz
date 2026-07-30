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
