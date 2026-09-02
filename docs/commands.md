# Commands — the full reference

> Relocated out of [`CLAUDE.md`](../CLAUDE.md) on 2026-09-02, verbatim.
> CLAUDE.md carries the RULE — one line, loaded every session; this file
> carries the incident that produced it. When the two disagree, CLAUDE.md
> is the operating instruction and this is the record of why.

Every CLI command and offline driver, with the reasoning each one encodes.
CLAUDE.md keeps a one-line index of the same set.

- `python -m clinkz scan --target <url|host|ip|cidr> [--scope <entry|scope.json>]
  [--exclude <entry>] [--authorization <auth.json> | --auth-* flags |
  --auth-prompt] [--creds <creds.json>] [--source <tree>] [--benchmark-profile
  <bp.json>] [--dry-run] [--rate-limit N] [--max-concurrency N] [--out <dir>]
  [--resume <id>]` — full pentest (recon → scan/research/exploit → report). The
  only end-to-end command. **Refuses to start without an authorization record**
  (`--auth-*` flags refuse with EVERY missing field named — the record has no
  partial shape); `--dry-run` enumerates what it WOULD do, including whether the
  `--source` tree is ingestable, and sends nothing. **It previews the benchmark
  profile that will ACTUALLY execute**, splitting the destructive categories into
  WILL BE REFUSED / WILL BE PERMITTED via the same `permits_category` predicate
  `benchmark_override` consults at dispatch, and rendering the sample classifier
  verdicts through it too. It used to build the refusal list from a module
  constant and never read the attached profile — so a run permitting `deletion`,
  `data_reset` and `unsafe_method` previewed as though all three were refused,
  and *the dry run is what a client authorizes against*: an under-reporting
  preview obtains consent for a different engagement than the one that runs.
  `unsafe_method` was absent from the list entirely and so appeared in neither
  column, on the very runs that permit it. `--out` redirects the whole
  bundle by setting `settings.outputs_root`, which every writer resolves at CALL
  time — a default argument would be bound at import and silently ignore it.
  `--resume` rebuilds an interrupted engagement's report from its persisted
  findings and sends nothing; it does not resume TESTING (phase coverage is not
  persisted, findings are), and the regenerated report says so in its own
  *What was NOT tested* section. **The exit-code contract is the interface**
  (`cli.py::EXIT_CODES`, rendered into `--help`, asserted by the test suite):
  0 completed · 1 failed · 2 bad input · 3 refused before testing · 4 halted ·
  5 completed but the bundle FAILED the disclosure gate.
- `python -m clinkz abort <engagement_id>` — kill switch: halt immediately and
  cleanly (the report is still produced).
- `python -m clinkz actions <engagement_id> [--outcome sent|refused] [--raw]` —
  every state-changing request the run produced: "what did it do to my app?".
- `python -m clinkz artifact-scan <engagement_id> [--bundle-only] [--raw]` — the
  disclosure gate, re-run by hand: does this bundle still carry credential
  material? Covers the engagement directory AND the companion artifacts beside
  it; `--bundle-only` asks the narrower question. Exits non-zero if so. Runs
  automatically at the end of every engagement.
- `python -m clinkz report-pdf <engagement_id> [--outputs-root <dir>] [--out <file>]`
  — re-render the client-facing PDF from `report_<id>.json`. **Offline**: it
  reads the stored, already-redacted structure and sends nothing, which is the
  whole point — three renderers, one source. For a bundle written before the
  governor stamped its request window it recovers the narrower window from that
  bundle's own `actions.jsonl` — the governor's own writer, inside the bundle —
  and renders the provenance beside it rather than presenting it as the full one. Every engagement writes this PDF
  itself; the command exists for a re-render after a layout fix, or for a bundle
  produced before the renderer did. Exits 2 on a missing bundle or unreadable
  report, 1 when the renderer is absent or the document could not be built.
- `python -m clinkz trace inspect <engagement_id>` — render an execution trace.
- `python -m clinkz tool-invoke <engagement_id> <seq> [--replay]` — inspect/replay
  one tool invocation.
- `python -m clinkz step-replay <engagement_id> <step_id>` — re-run one agent step.
- `python scripts/regrade_stored_bundles.py` — **offline** re-grade of every
  stored bundle's confirmed findings against the never-sent control and the
  attribution check. Sends nothing. Reports SURVIVES / **NO_ARM** / REFUSED /
  **UNKNOWN_CLASS** per class, holding "the question was never asked" apart from
  both answers: a stored bundle cannot dispatch a control, and a finding that
  was correct because the target was genuinely vulnerable but would fail its own
  control is a phantom that landed on a real bug. **A title that resolves to no
  `VulnClass` is UNGRADED, not a pass** — every verdict is read off the
  producer's declaration (`MARKER_ORACLE_CLASSES` / `VulnClass.control_arm`, all
  keyed by `_test_*`), and an unresolvable finding reaches none of them, so
  `control_required("") is False` was the consumer supplying an answer the
  producer never gave. The emit side is fixed at the same time:
  `vuln_classes.finding_title()` composes a title from the class's OWN first
  token so `for_finding` cannot fail to resolve it, and `_make_finding` logs an
  `UNCLASSIFIED FINDING` when one does. That matters beyond the re-grade — an
  unresolvable title exits every class-keyed rule, *including*
  `control_required`, so it leaves the never-sent-control gate rather than
  failing it. **And the description is a FALLBACK, which `for_finding` said and
  did not do**: it searched `title + description` as one string, so the longest
  token anywhere won — and a description is
  `Technique: <id>. Parameter: <name>.`, where the parameter name is a value the
  methodology or the target chose, not a class name. `client-side` (11) in
  `Parameter: (client-side fragment)` outranked `dom-based` (9) in the title, so
  P7's flagship browser-witnessed DOM-XSS was filed as
  `_test_javascript_attacks` at all three exploitable ladder levels — wrong
  remediation, wrong declared yield, wrong class in the re-grade. A title that
  resolves is authoritative.
- `python scripts/regrade_idor_arms.py <engagement id> --caller-token-fp <fp>
  --owner-token-fp <fp> --caller-identity <v,v> --owner-identity <v,v> [--json]`
  — **offline** re-grade of a stored bundle's confirmed IDOR findings through
  the ANCHORED oracle. Sends nothing; reads `trace.jsonl` plus the recorded
  `tool_invocations/` bodies, and tells principals apart by the bearer
  fingerprint the engine's own redactor already wrote, so the replay never holds
  a live token. Three verdicts, and the third is the point: **SURVIVES** ·
  **REFUTED** · **REDISPATCH_REQUIRED**, the last for a case whose corrected
  arms were never dispatched against the corrected reference. Reporting that as
  a pass is the acceptance-criterion mistake itself; reporting it as a failure
  claims a measurement nobody made.
- `python scripts/plan_variance_corpus.py [--outputs-root <dir>] [--json]` —
  **offline** replay of every recorded phase-3 ranking against the deterministic
  ranking layer. Sends nothing; reads only `outputs/*/trace.jsonl`, which already
  carries the phase-2 fingerprint, the order phase 3 produced and the type phase
  5 confirmed. Reports per class what the recorded window kept, what the new one
  keeps, the attempt cost, and how many fingerprints produced more than one
  order. Exits non-zero if the new window loses a confirmation the engine is
  known to have made.
- `python scripts/cve_reservation_corpus.py [--outputs-root <dir>] [--json]` —
  **offline** replay of what the dependency→CVE slot reservation would have cost
  every stored bundle. Sends nothing. Answers the two questions the reservation
  had to earn: a run that matched nothing plans **byte-identically**, and where
  it does apply the displaced Tier-1 count is stated. Neither input is stored
  whole — `report.hosts[].services` is empty on every bundle and `trace.jsonl`
  truncates the recon handoff at 500 chars — so the inventory is recovered by
  the strongest surviving route (report → handoff → the REAL fingerprint parsers
  over recorded stdout) and **the route is printed beside every number**; a
  bundle no route reaches is `UNRECOVERABLE`, never `0 components`, and a bundle
  whose `passes_recorded` is 0 has no baseline rather than a baseline of zero.
  Carries a **positive control** — the same bundles with the observed Apache
  version substituted for one the catalogue matches — because a corpus of zeros
  is evidence only once the instrument has registered a hit; a control that
  reserves nothing exits non-zero and says the zeros prove nothing. A second
  **package-identity control** covers the ingestion path, and its weaker form is
  stated rather than blurred: the Apache arm SUBSTITUTES a version into an
  observation the bundle really made, while this one INJECTS rows no stored
  bundle could ever have observed, because none records a served bundle body or
  a supplied lockfile. It asserts three claims separately — ingestion reaches
  the matcher, a lead-only match reserves nothing, and a lockfile-provenance
  match is ordered ahead of a banner one — the last written against the two
  provenance values BY NAME, because checking that the list is sorted by
  `version_provenance_rank` re-derives the expectation from the sorter's own key
  and passes with the rank table inverted. A run where no bundle carried both
  provenances exits non-zero: the claim passed having compared nothing.
- `python -m clinkz corpus-replay [--rebuild]` — **offline** parser regression gate:
  re-parses every recorded `tool_invocations/` stdout and diffs against
  `tests/fixtures/corpus_replay_baseline.json`; exits non-zero on drift. Sends
  nothing — unlike `tool-invoke --replay`, which RE-EXECUTES the recorded
  command against the live target and always exits 0.
- `python scripts/three_run_envelope.py --authorization <auth.json>
  --benchmark-profile <bp.json> --creds <creds.json> [--scope <scope.json>]
  [--runs 3]` — **LIVE.** N identical Juice Shop benchmark runs, each preserved
  under `outputs/_juiceshop_benchmark/envelope/run_<n>/` because the harness
  overwrites its own results directory every run. Carries the two guards a
  credit lapse needs: a **terminal account state refuses the batch** before
  anything is sent (exit 3) and a run whose `model_stamp` names an unserved
  stage is **not recorded** and ends the batch (exit 4). Variance is computed
  over the recorded runs only.
- `python scripts/juiceshop_benchmark_run.py --record-floor [<engagement id>]` —
  **offline.** Re-derive the crawl-and-authenticate floor from a stored
  zero-dispatch bundle, keyed to the credential set that bundle authenticated
  as. Refuses a run that tested, one whose dispatch count is unmeasurable, one
  with an unserved stage, and one that does not say who it logged in as.
- `docker compose -f docker/docker-compose.yml up -d` — start the test targets.
