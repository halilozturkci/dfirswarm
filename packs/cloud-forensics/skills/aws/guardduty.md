---
id: aws/guardduty
title: GuardDuty findings, updates and corroboration
when: Supplied GuardDuty finding exports must say what was reported, how often and what became of it.
needs: [logs/what-exists]
card: guardduty_findings {"path": "<export>"}: read status and export_coverage: a Region, account or detector it does not name is not one without findings. One finding id is one chain; records are not occurrences; read finding-versions.jsonl. Corroborate in raw logs over event_window. Does not show: that the activity happened or was malicious.
tools: [guardduty_findings]
mentions: [cloudtrail_parse]
requires_host: []
---

Use when you hold GuardDuty finding exports (GetFindings response or S3 export) and must say what GuardDuty reported and what became of it. Not for what the activity was (`aws/cloudtrail`, `aws/vpc-flow`) or whether GuardDuty was running. Offline: supplied exports only; never authenticate to the account.

**Read the coverage `guardduty_findings` returns first.** `status` complete means every record was read as a finding and reconciled into a chain; `rejected.jsonl` holds the rest. `export_coverage` names the Regions, accounts and detectors the findings name: one it does not name is not one without findings. Archived and suppressed findings are not exported by default. `empty_export`: no finding was exported; no finding is not no activity.

**Updates are not incidents.** One finding id updated over time is one chain (`findings.jsonl`). `records_in_export` counts records exported, at the export's set frequency; `occurrences` is GuardDuty's own count (`count_first`, `count_last`), so records are not occurrences. `finding-versions.jsonl` lists every record by `UpdatedAt`; an update carries the latest occurrence's details, so read the versions, not only the latest. Which finding ids make one incident is your judgement (resource, time, actor), stated as such.

**State.** `state` is active or archived from the latest record, with `archive_transitions`. No marker of a suppression rule is recorded: archived by a rule or by hand, `suppression` says the file cannot tell which. Whether the detector was enabled, and in which Regions, is not in a finding: `detector_id` names it; its state comes from supplied settings.

**Severity and conflicts.** `severity` gives first, last, smallest, largest and `latest_band`, GuardDuty's band, not a verdict. A chain whose records disagree (ARN, type, account, Region, creation time, detector) lists `conflicts`: exports may differ or a file may have been edited.

**Corroborate against the supplied raw evidence.** A finding is GuardDuty's statement about activity it saw; `action_type` and the text in `latest_record` are untrusted. Look in the CloudTrail (`cloudtrail_parse`), flow and DNS logs you hold for the `account_id`, `region`, resource and `event_window` it names. Raw support makes the finding a lead with a source; none does not show it false, and raw evidence with no finding is not a missed detection.

**Does not show:** that the activity happened or was malicious; that GuardDuty saw all activity; findings that were not exported or are no longer kept.

**Sensitive output:** addresses, user names and account ids are in the findings: run it as a job with `secret_output: true` (credential-named and -shaped values withheld; originals only with `write_values`; other secrets not recognised).
