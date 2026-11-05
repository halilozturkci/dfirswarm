---
id: logs/journal-clocks-verify
title: Journal clocks, identity fields and verify
when: Ordering journal entries across clocks and boots, or judging journal integrity.
needs: []
tools: [journal_export]
requires_host: [journalctl]
---

Use only if you order journal entries, rely on its attribution fields or judge integrity. Not for what was supplied and how the export is made (`logs/journal`).

**Clocks.** `realtime_us` is the wall clock and can be set, stepped or corrected within a boot; `monotonic_us` counts from the boot and is the order inside it. A boot id names a boot and orders nothing, so grouping by boot does not remove a clock step inside it. Within a boot order by monotonic time and look for the wall clock disagreeing with it (a step; suspend and merged files can also show as one, so name candidates, do not conclude). Across boots and across hosts anchor the clocks independently and carry the uncertainty.

**Identity fields.** `_PID`, `_COMM`, `_EXE`, `_CMDLINE`, `_UID`, `_SYSTEMD_UNIT` and `_AUDIT_SESSION` are journald's attribution at the time of logging. Their availability varies with the transport and the process's lifetime, and an `_EXE` path does not establish the executable's content or integrity (`packages/integrity`).

**Verification.** `journal_export` with `mode: verify` runs `journalctl --verify` on its own and keeps its whole output and exit code. It checks the structure of the files it was given. A clean result does not authenticate an unsealed journal, does not show that no file or entry was removed, and is not the same as Forward Secure Sealing, which needs a verification key held independently. Judge a gap against rotation, retention, the boundaries of what was collected, boot changes and remote copies: a sequence break alone does not show deletion.

**A journalctl that left a process.** `journal_export` is `partial` (`program_group`) when journalctl left a process running, or the host cannot show it did not; a process that holds the pipe is let go a second after journalctl ended.

Shows: the order inside a boot, journald's attribution at logging time, the structure check. Does not show: authenticity, completeness, or the true time across boots. Record: both clocks raw, the anchors, the `--verify` output and exit code, the gap and the alternatives weighed.

Sensitive output: `_CMDLINE` can hold secrets; cite the cursor and `native_line`, never the text or a hash of it.
