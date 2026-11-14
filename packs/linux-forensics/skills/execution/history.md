---
id: execution/history
title: Shell and client histories as evidence
when: Reading bash, zsh, fish or client histories for what was typed.
needs: []
card: shell_history {"root": "<home or extracted root>"}: the answer carries locators and lengths only; read the text with {"write_commands": true} in a job with secret_output: true, and cite file and record. Read each file's format first: bash has times only where HISTTIMEFORMAT was set, and a file without times gives order only. user is unknown unless the evidence's etc/passwd gives that home to one account. An empty or missing file is a question: killed or unflushed sessions, HISTCONTROL, HISTFILE unset, trimming, a link to /dev/null and concurrent shells remove commands; read the startup files. Does not show: that a command ran or succeeded, or who typed it.
tools: [shell_history]
requires_host: []
---

Use when you read command histories. Not for sessions and logins (`accounts/session-accounting`) or for what the auditing system recorded (`logs/auditd`).

A history file is what a program chose to save, when it saved it. `shell_history` reads bash, zsh and fish files and the plain histories of clients (`.python_history`, `.mysql_history`, `.psql_history`, `.rediscli_history` and others) record by record, and says how each record's boundaries were found. Read the format before the content: bash writes a `#<epoch>` line before a command only when `HISTTIMEFORMAT` was set, zsh's extended history keeps `: epoch:duration;command`, fish keeps a YAML-like list with `when`; a file without times gives order and nothing more. A multi-line command is one record in some shells and several in others, and the tool says which rule it used.

What a history lacks matters as much as what it holds. A shell writes its history on exit unless told to append, so a session that was killed, that ran in a container, or that was never flushed leaves nothing; `HISTCONTROL` (a leading space), `HISTFILE` unset, `HISTSIZE` and `HISTFILESIZE` trimming, a history file replaced by a link to `/dev/null`, concurrent shells that overwrite each other's entries and a custom `HISTFILE` path all remove commands. Look in the shell's startup files for those settings, and treat an empty or missing file as a question, not a finding.

Map a home directory to an account from the evidence's `etc/passwd`: `user` is `unknown` unless it gives that home to one account, and a directory's name is not an account. A recorded command shows neither that it ran nor that it succeeded, who typed it, nor where the shell was. An entry can be pasted, edited by hand or written by a script. Corroborate with the audit log (`logs/auditd`), the auth log and file times, and write the history line as a lead.

Shows: text a shell or client saved, in source order, with any recorded times. Does not show: that a command ran or succeeded, who typed it, or commands the shell did not save. Record: file, record, the format, the time source, the startup settings read, and what the file lacks.

Sensitive output: commands carry passwords, tokens and keys typed or pasted. Run `shell_history` as a job with `secret_output: true` and `write_commands: true` to read the text; without it the answer carries locators and lengths. Cite file and record, never the command or a hash of it.
