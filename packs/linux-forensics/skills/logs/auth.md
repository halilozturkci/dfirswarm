---
id: logs/auth
title: Authentication and privilege-use records
when: Interpreting retained auth records, their timestamp assumptions and attribution limits.
needs: [triage/system-profile]
tools: [auth_log, utmp_parse]
requires_host: []
---

    Debian family       /var/log/auth.log, auth.log.1, auth.log.*.gz
    Red Hat family      /var/log/secure and its rotations (often with a date suffix)
    Either              the systemd journal, which may hold the same lines (`logs/journal`)

These are candidate destinations, not guaranteed files. Read the rsyslog, journald and logrotate
configuration, then inventory every retained rotation and any remote copy; a missing rotation is a gap to
name. `auth_log` reads plain and gzip text, orders the files by their rotation suffix and says which basis
ordered each (`order_basis`, `cross_file_order`): a number or a date in the name orders a file, a name with neither
is ordered by name only, and a mix of schemes is reported as an order that is not established. Every record carries its file, physical line and byte offset.

**Time.** A traditional stamp has no year and no zone. `auth_log` takes the year from the file's modification
time (on a copied tree that is the time of the copy) or from your `year`, and says which per file
(`year_basis`); `time_raw` is the stamp as written, `time` the clock reading as written, `time_utc` is set only where the stamp carries
its zone, and `time_zone` is `unknown` until the profile establishes one (`triage/system-profile`). A month that goes down is read as a year
end (`rollovers`, `rollover_lines`) only where the way forward round the calendar to it is six months or fewer (December to January);
any other step back, and a line the next line contradicts, is flagged `reordered` and does not date the file, and the last line in
order, with a day's margin for the unknown zone, does. A month that goes up is later, whatever the gap: a log that skips from January
to September is not given a year end. An RFC 3339 stamp keeps its own offset. Read `unparsed` and `read_errors`
before trusting a count: `status` is `complete` only where `all_lines_parsed` is true, which says every line matched a syslog shape and
every file was read through, nothing more (a read that ran past `max_seconds` names the files it did not reach).

What the lines show, and what they do not:

| Line | Shows | Does not show |
| --- | --- | --- |
| `ssh_accepted` | sshd accepted an authentication by that method for that account from that address and port | a person; for `publickey`, only a key: `fingerprint` (and a certificate's `cert_id`, `ca_fingerprint`) must be resolved through the effective sshd policy (`accounts/users`); not when or by whom the key was installed |
| `key_observed_authentication` | sshd matched a login to an authorized_keys entry and, where the log level wrote it, which file and line | that the key was added then; the file's mtime is not the date of the line |
| `ssh_failed`, `ssh_invalid_user`, `auth_failure` | an attempt, with the source the line gives, and the user only where the log names an account (a rejected public key's fingerprint is kept) | a failed burst then one acceptance has several explanations: a stale saved credential, a legitimate mistake, unauthorised use. Compare the source with that account's history |
| `session_opened` | a PAM session for the service in `pam_service` (sshd, sudo, cron, systemd-user and others) | a login: correlate account, host, PID, time and the later session records |
| `sudo` | the logged authorization and invocation: user, tty, directory, target, command | the command's children or success; the line can be truncated, escaped or split by the logging path. Look for sudo I/O or subcommand logging and audit records where they were retained |
| `su`, `account_added`, `account_changed` | the logged event | who ran it or why |

`sudo -i` followed by no further line shows only that this log has no further line: what the shell ran is in
other sources (histories, the journal, audit records where auditd ran), and the report names which were
searched. A name typed at a prompt (the name on an `Invalid user` line, or a PAM `user=`) can be a password typed into the wrong field:
`auth_log` leaves it out of the answer and the paging file and gives its length (`user_bytes`, `user_withheld`) beside the line's
locator; the name is in the job's text file. Cite the locator, never the name; `utmp_parse` does the same for btmp.

**Corroboration.** Compare the sessions that matter with wtmp and btmp (`utmp_parse`, classic format only) and
with the journal. Differences among them can come from forwarding, filtering, retention, collection or parser
differences as well as from alteration, and these text files are editable by root: establish what each source
would have recorded before alleging an alteration, and report a disagreement as a question with the
alternatives, not as a finding.

**Sensitive output.** A sudo line is a command line. `auth_log` answers with fields and locators and no
`raw`, `command` or typed name; `write_text: true` writes them to a private file under `$OUT`, and `preview_text: true`
puts them in the answer, each only in a job run with `secret_output: true`. A `contains` filter outside a job matches only
what the answer shows. Cite the file and line, never the command, a typed name or a hash of either.
