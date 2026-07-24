---
description: Print the ARTIFACTS block for a local engagement run (the standing replacement for committing outputs/).
argument-hint: <engagement-id | outputs-subdir>
---
Print the **ARTIFACTS block** for the run identified by `$ARGUMENTS` (an
engagement id, or a path under `outputs/`). Run artifacts are local-only by
policy — never committed — so this block is how a run's evidence is surfaced.

1. Resolve the run directory to an **absolute** path (`outputs/$ARGUMENTS/`, or
   the given path). If it does not exist, list `outputs/` and stop.
2. For every file in the directory print: absolute path, size in bytes, and one
   line on what it evidences — e.g. `report.json` (findings + risk rating),
   `report.md` (human report), `trace.jsonl` (per-step execution trace),
   `live_run_stdout.log` (driver stdout), `*_before/after.json` (KB state deltas).
3. Explicitly flag any **expected** artifact that is NOT present. The standard
   set for a full run is `report.json`, `report.md`, `trace.jsonl`; a discovery
   validation driver additionally emits its own before/after dumps. Name each
   missing one.

Report the block verbatim — do not summarize or grade the findings.
