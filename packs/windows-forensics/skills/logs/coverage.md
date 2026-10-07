---
id: logs/coverage
title: What a silent or gapped event log shows
when: You are about to write that an event is absent, a channel empty or a record id missing.
needs: []
tools: [evtx_query, regkv]
requires_host: []
---

Use when a question turns on an event that is not there. Not for reading the file (`logs/security`) or for a log that was cleared (`logs/recovery`).

An event exists only if the channel was enabled, the audit subcategory or provider was on, and the file's size and retention kept it; what you hold also depends on what was collected. Before a negative:

1. Per file, take the first and last record time and the record count: the interval it can speak for. `evtx_query` without a filter keeps every record in file order in `result_file`; its first and last rows are the ends (`highest_record_id_read` is the top id).
2. Establish the channel's configuration (enabled, size, retention) with `regkv` in the SOFTWARE and SYSTEM hives and the policy keys, for example under `Microsoft\Windows\CurrentVersion\WINEVT\Channels` and `Policies\Microsoft\Windows\EventLog` (hive state: `registry/overview`). The pack does not decode a stored audit policy: use 4719 records, policy files the case holds, or events of the same subcategory in the logs. Such an event shows the subcategory was on then; its absence alone shows nothing.
3. Say what else could have written the silence: another machine, a service, a forwarder, a different channel.

An empty channel is a coverage condition to explain, not a verdict: disabled or never written, no such activity, overwritten, forwarded elsewhere, not collected, unreadable, or cleared.

- **Record ids.** EventRecordID orders the records of one file as the log service wrote them. It does not order two channels or files, and restarts with a new file generation. A gap means records are absent from that file (overwrite, clearing, filtering, collection); it does not count missing events.
- **Across channels.** Build a timeline from times, each source with its clock caveat. Where a clock moved, keep the record order and the times and mark the records near the change.
- **Parse status.** A negative over a `partial` run, or with `parse_errors` above zero, is bounded by what was read.

Sensitive output: `evtx_query` rows carry command lines and typed text; run it as a job with `secret_output: true` where the log may hold them (`logs/security`).

Shows: what this file, in this state, holds. Does not show: that an event never happened, or that a channel's absence of 1102 or 104 excludes a clearing. Record: files, first and last record time, counts, `parse_errors`, the configuration evidence, and the explanations left open.
