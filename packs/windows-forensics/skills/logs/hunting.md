---
id: logs/hunting
title: Rule-based event review with sigma_hunt
when: You search collected logs with a ruleset and must interpret detections and a clean result.
needs: []
tools: [sigma_hunt, evtx_query, evtx_carve]
requires_host: [zircolite, hayabusa]
---

Use when a first pass found nothing or the logs are too large to read by id. Not for logs that were cleared (`logs/recovery`).

`sigma_hunt` runs one engine, `zircolite` or `hayabusa`; either is enough, and `engine_version` is the one that ran (check the version the image carries). With neither on the host it says so, and the report line is that no rule-based sweep was performed, not that nothing was found.

- **Repeatably.** Name `engine`, `path`, `rules` and an `out_dir` of the form `work/<your id>/hunt` (in a job it lands in `$OUT`); any other place is refused, naming the places that work. Each call writes its own `hunt-<UTC time>-<id>` directory (`run_dir`): a result is never an earlier run's and nothing is replaced.
- **The ruleset.** `ruleset` carries its sha256 (a directory by its sorted paths and digests). With no `rules` the engine's bundled rules run and their content is not recorded, so the sweep cannot be repeated from the record. Rulesets are engine-specific.
- **Keep** `result_file`, the engine's stdout, stderr and logs, `command`, `exit_code` and `all_detections`. The engine's own output says how many rules it loaded and records it read; the tool does not count them.
- **Status.** `interrupted` (a stop by signal) is no result. `partial` is a non-zero exit, a stop at `timeout_seconds` or an unreadable result line (`malformed_lines`, kept whole in a file), and bounds every negative. `min_level` filters `detections.jsonl`; what it removed is `below_min_level`, and a level the tool does not know is kept, shown first and counted in `unknown_levels`.
- **A detection is a hypothesis with a name.** Take its computer, channel and record id to `evtx_query` (`start_record` and `end_record` the same id, on the file the channel lives in), read the whole record and cite that, with its own time rather than the engine's field. Severity is not confidence, and community rules are written for live estates: for each detection that matters, write the benign explanation you tested.
- **A clean result** has several explanations; say which you excluded: no matching activity; the channel off or not supplied (`logs/coverage`); no rule maps to this log's fields; the engine could not read a file or record (compare its count with `records_examined`); filtering; a failed run.
- **Carved records** (`evtx_carve`) are JSON, not an `.evtx`, and no adapter feeds them to an engine: read the carved XML (`logs/carving`). A whole `.evtx` recovered from a snapshot or a deleted file can be hunted like any log.

Shows: that no loaded rule matched in what was read, or which did. Does not show: that the technique was absent, happened or succeeded, or who did it. Record: engine and version, `ruleset`, files and interval, `min_level`, status, `malformed_lines`, `unknown_levels`.
Sensitive output: every detection carries the whole matched record, which can hold command lines and script text; run `sigma_hunt` as a job with `secret_output: true` when the logs may.
