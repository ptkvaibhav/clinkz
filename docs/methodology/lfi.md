# LFI — `_test_lfi`

Confirm **only on actual file content** (`_LFI_FILE_SIGNATURES` / base64-decoded
signature / source markers) — a filesystem path in a stack trace is information
disclosure, not a file read, and does not confirm LFI.

## Stack-awareness + file-content-only + `/ftp` poison-null-byte (Juice Shop 8df94e28)

- PHP wrappers (`php://*`, `data://`, `expect://`, `file://`) are probed **only on
  a PHP stack** (`_is_php_stack` over `self._technologies`, harvested from
  recon/scan/research in `run`); on Node every odd value 500s as "Unexpected path"
  and that divergence is no longer mistaken for wrapper support.
- A static **file-server sub-methodology** (`_test_lfi_file_server`) handles
  param-less routes like `/ftp/<file>`: enumerate the directory (served listing ∪
  a bounded backup wordlist) and, for a file *blocked when requested directly*,
  attempt the poison-null-byte extension-allowlist bypass (`<file>%2500.md`),
  emitting only when the bypass returns real, non-SPA file content.
  `_applicable_methods_for_endpoint` queues `_test_lfi` for param-less file-server
  paths so `/ftp` reaches LFI at all. Bounded, same-origin, regex-only.

## Bypass-adaptive `file://` wrapper (Bucket-B DVWA `high`)

DVWA fi/high filters relative traversal (`fnmatch("file*", $file)`) — naive `../`
returns "ERROR: File not found!".

- Phase-4 wrapper synthesis is generalised beyond `php://filter`: a confirmed
  `file://` emits `file:///etc/passwd` (absolute read that bypasses the
  relative-traversal filter, verified by /etc/passwd signature) and phase 3 ranks
  wrapper extraction first for any confirmed non-php-filter wrapper — the path
  that confirms fi/high.
- Phase-2 records a working **traversal** sequence ONLY on a real /etc/passwd
  content signature (a block/error page that merely diverges from the include.php
  baseline is no longer mistaken for a working `../`), and **wrapper** detection is
  signal-based not divergence (`data://` requires its inline payload rendered back;
  `php://input`/`expect://`, unconfirmable by a GET probe, are no longer recorded
  on divergence — removing the block-page false wrappers).
- Prefix-preserving traversal: naive-blocked + a leading token in the original
  value → `<token>/../../../../etc/passwd` (best-effort; phase 5 still confirms
  only on real file content, so a token that isn't a real directory fails cleanly).
  Low/medium still confirm; impossible (whitelist) emits nothing. The now-unused
  `_LFI_WRAPPERS` constant was removed.

## PR#75 real-pipeline regression fix (LESSONS #18/#28)

The keyless suite pins a silent LLM and only exercised the deterministic fallback,
hiding two live-LLM misses:

- **(A) genuine-read regression** — with recon naming PHP, the live Anthropic
  synthesis appended a dead `%00` to the phase-2-confirmed absolute `/etc/passwd`
  read (inert on PHP 8.5.6), so phase 5 re-probed a broken payload and low/medium
  stopped confirming. Phase 4 now **prefers the empirically-grounded deterministic
  build** (`_lfi_primitive_confirms`) whenever phase 2 confirmed the read
  (absolute/traversal/nul/wrapper), **skipping the LLM** for that type; phase 3
  **floats the confirmed retrieval type ahead** of the LLM ordering (re-adding any
  it dropped) so it is never lost from the phase-5 tried window.
- **(B) file:// never probed at high** — recon/research LLM tech-extraction is
  flaky and silently omitted PHP (the only PHP signal on DVWA is the
  `X-Powered-By` *header* the harvest never reads). `_is_php_stack()` now backstops
  the tech list with a **`PHPSESSID` session cookie** (ground-truth PHP — only
  PHP's session handler sets it; Node/Juice-Shop never do).

Re-validated on the **real pipeline** at all four levels: low/medium confirm the
genuine `/etc/passwd` read, high confirms `file:///etc/passwd` (phase-2
`wrappers=['file://']`, 2 real reads), impossible emits nothing.

## Trailing-path-segment file read (`_test_lfi_path_traversal`, CVE-2020-17519)

**The gap.** A route that reads a file named by its **trailing path segment**
carries no query parameter and no declared `:placeholder`, so the per-parameter
methodology has nothing to iterate. The file-server sub-methodology
(`_test_lfi_file_server`) gates on a directory-NAME allowlist (`/ftp`, …) that
cannot enumerate every such route. Apache Flink's `/jobmanager/logs/<file>` is
exactly this shape, and `logs` is on no allowlist, so the black-box engine had no
path to it.

**The probe.** For a param-less route nested under a collection (at least two
path segments, last segment not a static-asset extension —
`_is_static_path_traversal_candidate`), `_test_lfi` also runs
`_test_lfi_path_traversal`. For each canonical target and each traversal
sequence, it appends the sequence × 8 + the target as one trailing segment through the existing path carrier (`_path_send_probe`;
`_substitute_path_segment_raw` appends when there is no placeholder), with the
slashes normalised to the carrier's encoded-slash token so the whole traversal
stays ONE opaque segment. Queuing is a STRUCTURAL signal, not a directory-name
list, and it is an independent branch, so it never shadows the session-setter
SQLi route. Bounded at 25 routes per engagement, each probed once.

**The confirmation.** A canonical-file signature (`_LFI_FILE_SIGNATURES`) in the
traversal response is only a candidate. It confirms through `_run_control_arm`
(invariant 27): the arm sends a benign trailing segment and must REFUSE, meaning
the signature must be absent, so a route that echoes its segment or reads no file
emits nothing. The finding names the file read and the control, never a version
string. The version is never consulted.

**Live.** Rediscovered black-box on Vulhub Flink 1.11.2: `GET /jobmanager/logs/`
plus a double-encoded traversal segment returned `/etc/passwd`, and the control
arm refused on a benign segment. It took two fixes: this probe, and recon's
`ReconService.is_http` reading `-sV` protocol evidence. Before that, port 8081
(nmap: `blackice-icecap`) was marked non-HTTP and drew zero exploit tasks.

**Known gap, stated.** The candidate predicate's docstring says a static asset
such as `/main.1a2b.js` is excluded. It is not: the check is
`ext not in STATIC_ASSET_EXTENSIONS`, and `js` is absent from that set (register
R1). So a nested `.js` bundle is a candidate. The control arm keeps this honest,
because a bundle reads no file and so emits nothing, but a route that reads no file never short-circuits. It costs the
full `|signatures| × |sequences|` probes (5 × 7 = 35 today) plus a slot of the 25-route budget. This should be
fixed together with R1.
