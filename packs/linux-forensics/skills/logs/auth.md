---
id: logs/auth
title: Authentication and privilege-use records
when: Reading retained auth logs, their timestamp assumptions and attribution limits.
needs: []
card: auth_log {"path": "<auth.log, secure or their directory>"} reads plain and gzip rotations oldest first: read order_basis and cross_file_order, then status, unparsed and read_errors; status is the parse, not coverage. A missing rotation is a gap. Before you date or count lines, read year_basis and time_zone (logs/auth-time). Compare sessions with utmp_parse and the journal; a disagreement is a question, not alteration. Sudo commands and typed names need write_text in a secret_output job. Does not show: a person, or that an absent line did not happen.
tools: [auth_log, utmp_parse]
requires_host: []
---

Use when you read `auth.log` or `secure`. Not for what each line type shows (`logs/auth-lines`, only if you interpret a line), for year and rollover rules (`logs/auth-time`, only if you convert stamps) or for the journal (`logs/journal`).

    Debian family       /var/log/auth.log, auth.log.1, auth.log.*.gz
    Red Hat family      /var/log/secure and its rotations (often with a date suffix)
    Either              the systemd journal, which may hold the same lines (`logs/journal`)

These are candidate destinations, not guaranteed files. Read the rsyslog, journald and logrotate configuration, then inventory every retained rotation and any remote copy; a missing rotation is a gap to name. `auth_log` reads plain and gzip text, orders the files by their rotation suffix and says which basis ordered each (`order_basis`, `cross_file_order`): a number or a date in the name orders a file, a name with neither is ordered by name only, and a mix of schemes is reported as an order that is not established. Every record carries its file, physical line and byte offset.

**Time.** A traditional stamp has no year and no zone: `auth_log` states the year and zone basis per file (`year_basis`, `time_zone`; `triage/system-profile` and `triage/clocks-boots` fix the zone), and its `status` is about the parse, not about coverage. Before you date, order or count lines, read `logs/auth-time` (only if you convert or compare stamps).

**Corroboration.** Compare the sessions that matter with wtmp and btmp (`utmp_parse`, classic format only) and with the journal. Differences among them can come from forwarding, filtering, retention, collection or parser differences as well as from alteration, and these text files are editable by root: establish what each source would have recorded before alleging an alteration, and report a disagreement as a question with the alternatives, not as a finding.

Shows: what the logging services wrote, in file and line order. Does not show: a person, or that an absent line did not happen (`logs/auth-lines` per line type). Record: files and rotations read, `order_basis`, `year_basis`, `status`, `unparsed`, `read_errors`.

Sensitive output: a sudo line is a command line. `auth_log` answers with fields and locators and no `raw`, `command` or typed name; `write_text: true` writes them to a private file under `$OUT`, and `preview_text: true` puts them in the answer, each only in a job run with `secret_output: true`. A `contains` filter outside a job matches only what the answer shows. Cite the file and line, never the command, a typed name or a hash of either.
