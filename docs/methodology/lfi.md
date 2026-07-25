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
