---
id: logs/journal
title: Journal coverage, record identity and clock domains
when: Examining supplied systemd journals without losing fields or confusing clock order.
needs: [triage/system-profile]
tools: [journal_export]
requires_host: [journalctl]
---

    /var/log/journal/<machine-id>/*.journal    persistent storage
    /run/log/journal/...                       volatile storage; in the evidence only if /run was captured
    rotated and archived files (*.journal, *.journal~), a namespace's directories, a remote copy

Inventory what was supplied: each location, each file, the machine id, the namespaces and any forwarded
copy; then read the journald configuration and its drop-ins (storage, retention, forwarding) from the evidence.
A missing `/var/log/journal` shows only that this path was not found in what was examined. It does not show the
historical storage policy, and it does not exclude journals that were deleted, mounted elsewhere, forwarded or
not collected. State the boots and time range actually examined (`boots` in the answer).

`journal_export` runs `journalctl` with `--file` or `--directory` at the evidence path, and never at this
machine's journal: quote the path it read. Run it as a job with `secret_output: true` and `write_text: true`
to keep the native export (`-o json --all`, every field, byte for byte) in `$OUT/journal-native.jsonl`; that
file is the lossless result. The answer's projection carries, for each entry: `cursor`, `realtime_us` and
`monotonic_us` raw with the decoded UTC `time`, `boot_id`, `machine_id`, the source clocks where present, the
identity fields (`pid`, `uid`, `comm`, `exe`, `unit`, `audit_session`, `syslog_identifier`, `transport`) and
`native_line`; a field journalctl wrote as bytes or as null is named, not turned into text. Pass `since` and
`until` with their zone (`UTC` suffix or `@epoch`): a bare time is read in this machine's zone and is refused. A
journal directory that holds links is refused too, because journalctl may follow them out of the evidence: pass each
real file. An entry over 32 MiB is counted and located (`parse_errors.oversized_lines`) and is in the native file.

**Clocks.** `realtime_us` is the wall clock and can be set, stepped or corrected within a boot;
`monotonic_us` counts from the boot and is the order inside it. A boot id names a boot and orders nothing, so
grouping by boot does not remove a clock step inside it. Within a boot order by monotonic time and look for
the wall clock disagreeing with it (a step; suspend and merged files can also show as one, so name candidates,
do not conclude). Across boots and across hosts anchor the clocks independently and carry the uncertainty.

**Identity fields.** `_PID`, `_COMM`, `_EXE`, `_CMDLINE`, `_UID`, `_SYSTEMD_UNIT` and `_AUDIT_SESSION` are
journald's attribution at the time of logging. Their availability varies with the transport and the process's
lifetime, and an `_EXE` path does not establish the executable's content or integrity (`packages/integrity`).

**Verification.** `journal_export` with `mode: verify` runs `journalctl --verify` on its own and keeps its
whole output and exit code. It checks the structure of the files it was given. A clean result does not
authenticate an unsealed journal, does not show that no file or entry was removed, and is not the same as Forward
Secure Sealing, which needs a verification key held independently. Judge a gap against rotation, retention, the
boundaries of what was collected, boot changes and remote copies: a sequence break alone does not show
deletion.

**Does not show.** Entries that were never written, were rotated away or were not collected; that the
`MESSAGE` is true; who ran a command whose `_CMDLINE` it carries.

**Sensitive output.** Journal messages and `_CMDLINE` can hold passwords and tokens. The answer carries their
length only; `write_text: true` and `preview_text: true`, each only in a job run with `secret_output: true`,
give the text. Cite the cursor and `native_line`, never the text or a hash of it.
