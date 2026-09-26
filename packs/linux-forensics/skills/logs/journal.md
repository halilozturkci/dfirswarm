---
id: logs/journal
title: The systemd journal
when: The host runs systemd and you need what the text logs do not carry.
needs: [logs/auth]
tools: [journal_export]
requires_host: [journalctl]
---

    /var/log/journal/<machine-id>/*.journal    persistent, survives a reboot
    /run/log/journal/...                       volatile, gone at shutdown

If `/var/log/journal` does not exist, the journal was never persistent on this
machine and everything before the last boot is gone. That is a configuration
fact worth one line in the report, not a gap in your work.

`journal_export` shells out to `journalctl --file`/`--directory` and returns
every record as JSON. Keep the evidence mount read-only and retain all stderr;
never let a repair or vacuum command near the evidence. Use `journalctl
--verify` separately and preserve its complete result.

What the journal has that `/var/log/auth.log` does not:

- **`_PID`, `_COMM`, `_EXE`, `_CMDLINE`** on most entries, so a message can be
  tied to the binary that produced it rather than to a program name in the text.
- **`_UID`, `_AUDIT_SESSION`, `_SYSTEMD_UNIT`**, which is how you tie a line to
  a service and a login session.
- **`_BOOT_ID`**, which groups everything from one boot. Order by boot first and
  by time second, and a clock change stops mattering.
- **Entries from units that never wrote to syslog at all.**

Two cautions a reviewer will raise:

1. **The journal is not tamper-evident in the way people assume.** It has
   sequence numbers and per-file hashes, and Forward Secure Sealing exists, but
   it is off by default. A root user can delete a journal file. Missing files in
   an otherwise continuous sequence are the thing to look for, and
   `journalctl --verify` reports what it can.
2. **`journalctl` on your own machine reads your own journal by default.** Pass
   `--file` or `--directory` at the evidence, always, and quote the path you
   read in the report. This is the Linux version of the timezone mistake, and it
   is just as easy to make.
