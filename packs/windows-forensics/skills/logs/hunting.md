---
id: logs/hunting
title: Sigma review
when: Rule search over logs; read detections.
needs: []
tools: [sigma_hunt, evtx_query, evtx_carve]
requires_host: [zircolite, hayabusa]
card: sigma_hunt {"path": "<winevt directory>", "out_dir": "work/<your id>/hunt"}: with no engine on the host, no sweep was performed; partial bounds every negative. A detection is a hypothesis: cite the record itself, read with evtx_query. Does not show: that a technique was absent or happened.
---

Use when a first pass found nothing or the logs are too large to read by id. Not for logs that were cleared (`logs/recovery`).

`sigma_hunt` runs one engine, `zircolite` or `hayabusa` (`engine_version` is the one that ran). With neither on the host it says so, and the report line is that no rule-based sweep was performed, not that nothing was found.

- **Repeatably.** Name `engine`, `path`, `rules` and an `out_dir` of the form `work/<your id>/hunt` (in a job it lands in `$OUT`); any other place is refused. Each call writes its own `hunt-<UTC time>-<id>` directory (`run_dir`), so nothing is replaced.
- **The ruleset.** `ruleset` carries its sha256 (a directory by its sorted paths and digests). With no `rules` the engine's bundled rules run unrecorded, so the sweep cannot be repeated. Rulesets are engine-specific.
- **Keep** `result_file`, the engine's stdout, stderr and logs, `command`, `exit_code` and `all_detections`. The engine's own output counts the rules loaded and records read; the tool does not.
- **Status.** `interrupted` (a stop by signal) is no result. `partial` is a non-zero exit, a stop at `timeout_seconds` or an unreadable result line (`malformed_lines`, kept whole in a file), and bounds every negative. `min_level` filters `detections.jsonl`; what it removed is `below_min_level`, and a level the tool does not know is kept, shown first and counted in `unknown_levels`. Run once at `informational` so no level is dropped, then read by level.
- **A detection is a hypothesis with a name.** Take its computer, channel and record id to `evtx_query` (`start_record` and `end_record` the same id, on the file the channel lives in), read the whole record and cite that, with its own time rather than the engine's field. Severity is not confidence: for each detection that matters, write the benign explanation you tested.
- **A clean result** has several explanations; say which you excluded: no matching activity; the channel off or not supplied (`logs/coverage`); no rule maps to this log's fields; the engine could not read a file or record (compare its count with `records_examined`); filtering; a failed run.
- **Carved records** (`evtx_carve`) are JSON, not an `.evtx`, and no adapter feeds them to an engine: read the carved XML (`logs/carving`). A whole recovered `.evtx` is hunted like any log.

Shows: that no loaded rule matched in what was read, or which did. Does not show: that the technique was absent, happened or succeeded, or who did it. Record: engine and version, `ruleset`, files and interval, `min_level`, status, `malformed_lines`, `unknown_levels`.
Sensitive output: every detection carries the whole matched record, which can hold command lines and script text; run `sigma_hunt` as a job with `secret_output: true` when the logs may. Describe a found secret by where it sits, its kind, length and what it grants, never its value, a fragment or a digest.
