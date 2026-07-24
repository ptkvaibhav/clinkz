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
