---
id: timeline/super
title: Build and validate a scoped machine timeline
when: Broad parser output can find events or widen coverage.
needs: []
tools: [timeline_super, catalog_search]
requires_host: [log2timeline, psort, pinfo]
---

Use when broad parser output could find the window an incident happened in or widen source coverage. Not for the facts you cite (`timeline/build`). Parsers, zone and export: `timeline/super-scope`.

Two timelines, two jobs. The ledger is yours: facts you decided were worth recording, each cited and defensible. A super timeline is the machine's: what the enabled parsers produced from the sources they could read, not every timestamp on the volume. Keep its scope, parser selection, inaccessible sources and errors with it, and never present it as the first.

Run `timeline_super` as a job with the source objects declared and a new directory. A job writes only `$OUT`: `out_dir` is a directory under `{OUT}` (the default there), a path under your own `work/<you>/` is rewritten to it, and `work/timeline` is not writable:

    timeline_super  source=inputs/disk.E01  out_dir={OUT}/timeline  parsers="<names>"

**Read the result before you trust it.** `status` is `complete` (both programs exited 0, wrote their files and every line parsed), `partial` or `failed`; `collect_exit` and `export_exit` are the programs' own; `invalid_lines` counts output lines that were not events. `complete` means the pipeline finished, not that every parser read every source: Plaso's own processing report of the storage file (`pinfo`) says what each parser did, and a negative should not rest on the timeline before you have read it (`evidence/coverage`). Partial output can support a qualified observation, never an absence. An existing output directory is refused unless `resume` is true; then new files sit beside the earlier ones (`timeline.2.jsonl`), never over them.

**Use it like this.** Find the window first, then work the artefacts: bracket the hours that matter, then go to the artefact family's own skill for anything you claim. For each material event cite the sealed parser output and the artefact's own locator, then check what the timestamp means. A row can be cited, is not self-validating, and establishes no actor or cause. Never paste the timeline into the report: take the rows that matter into the ledger with `record`, each with its artefact, and keep the filter, zone, versions and exit codes beside it (`timeline/super-scope`).

This pack declares `log2timeline`, `psort` and `pinfo`; a declaration does not install them. Check the worker image's inventory, and when Plaso is missing say so rather than implying a timeline was built and found nothing. `catalog_search which=timeline` reads a partition's own timeline, not a Plaso output.

**Does not show.** A row shows what a parser read from an artefact, in UTC. It does not show that the event happened when the artefact's own clock says, who caused it, that every source was read, or that an event with no row did not happen.

**Sensitive output.** The timeline, the storage file and the `sample` in the answer are text the parsers read from the evidence: command lines, URLs with their parameters, names. When the source may hold credentials or tokens, run the job with `secret_output: true`, ask for `sample: 0`, and cite rows by their locator, never by their text.
