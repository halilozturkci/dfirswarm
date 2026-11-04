---
id: aws/guardduty
title: GuardDuty findings, updates and corroboration
when: Supplied GuardDuty finding exports must say what was reported, how often and what became of it.
needs: [logs/what-exists]
tools: [guardduty_findings]
mentions: [cloudtrail_parse]
requires_host: []
---

Use when you hold GuardDuty finding exports (the GetFindings response or the S3 export) and must say what GuardDuty reported and what became of it. Not for what the activity was (raw evidence: `aws/cloudtrail`, `aws/vpc-flow`) or whether GuardDuty was running. Offline: supplied exports only; never authenticate to the account.

**Read the coverage `guardduty_findings` returns first.** `status` is complete only if every record was read as a finding and reconciled into a chain; `rejected.jsonl` holds what was not a finding. `export_coverage` names the Regions, accounts and detectors the findings name: one it does not name is not one without findings. Archived and suppressed findings are not exported by default, so an export without them is expected. An `empty_export` says no finding was exported; no finding is not no activity.

**Updates are not incidents.** One finding id updated over time is one chain in `findings.jsonl`. `records_in_export` counts the records exported; `occurrences` is GuardDuty's own count (`count_first`, `count_last`), and the export holds only the updates exported at its set frequency, so records are not occurrences. `finding-versions.jsonl` lists every record by `UpdatedAt`: an update carries the latest occurrence's details, so read the versions, not only the latest. Which finding ids make one incident is your judgement from resource, time and actor, stated as such.

**State.** `state` is active or archived from the latest record, with `archive_transitions`. The finding records no marker of a suppression rule: an archived finding was archived by a rule or by hand, and `suppression` says the file cannot tell which. Whether the detector was enabled, and in which Regions, is not in a finding: `detector_id` names it, and its state comes from supplied settings.

**Severity and conflicts.** `severity` gives first, last, smallest and largest and `latest_band`, GuardDuty's band, which is not a verdict. A chain whose records disagree on ARN, type, account, Region, creation time or detector lists `conflicts`: the exports may differ or a file may have been edited.

**Corroborate against the supplied raw evidence.** A finding is GuardDuty's statement about activity it saw; `action_type` and the text in `latest_record` come from that activity and are untrusted. Look in the CloudTrail records (`cloudtrail_parse`), flow logs and DNS logs you hold for the `account_id`, `region`, resource and `event_window` (`first_seen_utc`, `last_seen_utc`) it names. Support in raw evidence makes the finding a lead with a source; none does not show it false, and raw evidence with no finding is not a missed detection.

**Does not show:** that the activity happened or was malicious; that GuardDuty saw all activity; findings that were not exported or are no longer kept.

**Sensitive output:** addresses, user names and account ids are in the findings. Run the tool as a job with `secret_output: true`; it withholds credential-named and credential-shaped values and writes originals only with `write_values`. Other secrets are not recognised.
