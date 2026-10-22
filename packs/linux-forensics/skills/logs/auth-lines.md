---
id: logs/auth-lines
title: What each auth log line shows
when: Interpreting ssh, sudo, su, PAM and account lines, and names typed at a prompt.
needs: []
tools: [auth_log, utmp_parse]
requires_host: []
---

Use only if you interpret a parsed auth line. Not for file order, year and zone (`logs/auth`).

| Line | Shows | Does not show |
| --- | --- | --- |
| `ssh_accepted` | sshd accepted an authentication by that method for that account from that address and port | a person; for `publickey`, only a key: `fingerprint` (and a certificate's `cert_id`, `ca_fingerprint`) must be resolved through the effective sshd policy (`accounts/users`); not when or by whom the key was installed |
| `key_observed_authentication` | sshd matched a login to an authorized_keys entry and, where the log level wrote it, which file and line | that the key was added then; the file's mtime is not the date of the line |
| `ssh_failed`, `ssh_invalid_user`, `auth_failure` | an attempt, with the source the line gives, and the user only where the log names an account (a rejected public key's fingerprint is kept) | a failed burst then one acceptance has several explanations: a stale saved credential, a legitimate mistake, unauthorised use. Compare the source with that account's history |
| `session_opened` | a PAM session for the service in `pam_service` (sshd, sudo, cron, systemd-user and others) | a login: correlate account, host, PID, time and the later session records |
| `sudo` | the logged authorization and invocation: user, tty, directory, target, command | the command's children or success; the line can be truncated, escaped or split by the logging path. Look for sudo I/O or subcommand logging and audit records where they were retained |
| `su`, `account_added`, `account_changed` | the logged event | who ran it or why |

`sudo -i` followed by no further line shows only that this log has no further line: what the shell ran is in other sources (histories, the journal, audit records where auditd ran), and the report names which were searched.

A name typed at a prompt can be a password typed into the wrong field. `auth_log` withholds it by its position in a line it recognises, not by what it looks like: the name of an `Invalid user` or `Illegal user` line (to the last `from <address>`, spaces included), of `Failed <method> for invalid user` or `illegal user`, of `Disconnected from invalid user`, and a PAM `user=` (the rest of the line) or `ruser=`. It leaves the name out of the answer and the paging file and gives its length (`user_bytes`, `user_withheld`) beside the line's locator; the name is in the job's text file. A line the tool does not recognise is `other` and prints no field. Cite the locator, never the name; `utmp_parse` does the same for btmp.

Shows: per line type, in the table. Does not show: per line type, in the table; none of them names a person. Record: line locator, the type, the service and the address or fingerprint the line gives.

Sensitive output: typed names, sudo commands and fingerprints of rejected keys; the locator is what you cite.
