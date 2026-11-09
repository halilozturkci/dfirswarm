---
id: analysis/engines-and-coverage
title: Zeek and Suricata analysis, and its coverage
when: A finding rests on what Zeek or Suricata produced, or on their silence.
needs: []
tools: [zeek_run, suricata_run]
requires_host: []
---

Use when a conclusion rests on engine output. Not for reading one fingerprint or alert (`metadata/fingerprints`) or for the capture's own scope (`capture/what-you-have`). Running an engine is not analysis, and analysis is not detection coverage.

1. **Take the receipt first.** `zeek_run` and `suricata_run` take `dry_run: true` and read no capture. The receipt gives the engine version, the digests of the policy script, rules and configuration, the engine's own load numbers (`rule_load`, `script_load_status`), the log outputs and `not_covered`. It says what would be used, not what would match. A command the build lacks (`dump_config` in `effective_configuration`) is named there, not guessed.
2. **Record what makes a rerun the same:** engine version and image digest, loaded scripts and plugins, configuration, ruleset identity (source, licence, SHA-256, rule counts; no ruleset ships with the pack and none is downloaded during a case), checksum mode (`checksum_mode`, `checksum_validation`), stream-depth limits and the output schema.
3. **No alert is a statement about the ruleset.** Rules that failed to load, were commented out or target protocols the traffic did not carry cover nothing. When `rule_load.known` is false nothing shows a rule loaded.
4. **A missing log is not a missing event.** A Zeek log exists only when a loaded script wrote it; compare `logs_requested_not_written` with `logs_empty`, and read `engine_diagnostics` before concluding.
5. Two engines, or two versions, that disagree are a finding about the engines until the cause is found.
6. **A process the engine left behind makes the answer `partial`.** If the engine exits 0 and leaves a process running, the tool ends it before it reads the logs (`program_group.left_behind`) and answers `partial`; so does a host that cannot show there was none (`program_group.unproven`, not Linux). The logs are what the engine had written when the process was ended: say so, and do not call the run complete.

Shows: what this engine, configuration and rules produced on this input. Does not show: what another build or ruleset would, or that traffic outside the rules was benign. Record: versions, digests, the dry-run receipt, checksum mode, what the rules target.
Sensitive output: EVE and Zeek logs carry URLs and names; run as a job with `secret_output: true`.
