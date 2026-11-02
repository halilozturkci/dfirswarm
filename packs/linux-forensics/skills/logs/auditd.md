---
id: logs/auditd
title: auditd records, events and what ran
when: Reading audit.log for executed commands and logins, and for what auditd did not record.
needs: []
tools: [audit_events]
requires_host: [ausearch]
---

Use when audit.log or its rotations are in the evidence and the question is what ran or who logged in. Not for authentication lines (`logs/auth`) or for the journal (`logs/journal`).

First read what auditd was set to record: the rules (`etc/audit/rules.d`, `audit.rules`), `auditd.conf` (log path, rotation, what happens when the disk fills) and whether the service ran. A log holds only what a rule selected, so an absent event is bounded by those rules, by the backlog (`lost_and_daemon_records` lists every `lost=` counter and DAEMON record) and by the rotations you collected (`rotation_gaps`, `gaps_between_files`). Without the rules, an absence says nothing.

`audit_events` takes `paths`, an ordered list (oldest first), and groups records into events by the stamp `audit(seconds.fraction:serial)` across rotations. One execution is several records (SYSCALL, EXECVE, CWD, PATH, PROCTITLE) of one group: read them as one event. Read `missing_components` before you quote an event (a PATH short of `items`, EXECVE arguments short of `argc`, an execve with no EXECVE or PROCTITLE). The serial restarts after a reboot or an auditd restart, so a stamp with its serial identifies an event, not a serial alone; a `serial_resets`, `continued_group` or `time_regression_runs` entry says where that happened.

`auid` is the login uid the kernel set at login and keeps through `su` and `sudo` (4294967295 is never set, and the entry is marked `unset`); `uid`, `euid` and the rest belong to the process. A SYSCALL's `success` is that system call's result and not the command's: a succeeded execve is a program started, a failed one an attempt. Say which clock the stamps are on before you put them beside the journal's.

`compare_ausearch`, in a job run as secret output, runs the installed `ausearch` on a sample of the first file and says `agree`, `disagree` or `not_run`: a second reader of 2,000 lines, not a check of the log.

Shows: events that auditd's rules selected, with numeric fields and the lengths of their text. Does not show: that a command reached its aim, anything the rules left out, or an event lost to the backlog. Record: the rules and `auditd.conf` read, the files in the order given, `rotation_gaps`, `lost_and_daemon_records`, the event locators.

Sensitive output: command lines, `exe`, `cwd` and path names are lengths in the answer. The text is in the file `write_text: true` writes in a job run with `secret_output: true`. Cite file and line, never the command or a hash of it.
