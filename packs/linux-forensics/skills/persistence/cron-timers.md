---
id: persistence/cron-timers
title: cron tables and systemd timers
when: Inventorying scheduled jobs with cron_dump and reading what it did not read.
needs: []
card: cron_dump {"root": "<extracted root>"} is a candidate inventory: read unsupported (at jobs, anacron, .service ExecStart, drop-in merging) and check those by hand. A listed job is not shown to have run; @reboot and OnBootSec are not calendar times. Units under run/ exist only if /run was captured. unparsed lines keep the status partial: read them. Text needs write_text in a secret_output job. Does not show: that a job ran or when.
tools: [cron_dump]
requires_host: []
---

Use only if the sweep reaches cron or systemd timers. Not for units and the sweep's frame (`persistence/mechanisms`).

`cron_dump` is a candidate inventory, not a scheduler: it lists `/etc/crontab`, `/etc/cron.d`, the cron.hourly to monthly directories, the Debian-style and Red Hat-style user spools and systemd timers (system, user and each account's own directories), each with its file, line, modification time and mode, and it names what it did not read (`unsupported`: at jobs, anacron, `.service` ExecStart, drop-in merging). It looks in the generator and runtime unit directories under `run/` too, but an acquired disk image holds them only where `/run` was captured, so an empty result there is not a negative. Check what it names as unread by hand, and validate run-parts selection and execute permission, which scheduler was installed, and time zone and daylight-saving behaviour. An `@reboot` entry is a trigger at the cron daemon's start, and a timer with `OnBootSec` counts from boot: neither is a calendar time, and neither shows that the job ran or when. A listed job is not shown to have run. A timer's row shows its first 50 assignments (`assignment_count`, `assignments_not_shown`); the rest are in `pages.assignments`, and `write_text: true` in a job keeps every assignment as a row of its own. A table line whose first word after the schedule is not `root`, an account of the evidence's passwd or a lower-case name (it may be the command of a line written without a user field), or whose month or weekday field is not a schedule, is `unparsed` (its text is in the text file) and keeps the status partial; so do cronie's `L`, `W`, `#` (as in `5#2`) and `?` and a numeric user (`1000`), an honest partial and no read failure. Its paging files stop at 128 MiB together (`not_written`, `assignments_not_paged`: counted, located by file and line, and partial). Inline entries stop at 1 MiB (`answer_budget`, `truncated`); `pages.entries.all_results` holds all of them, with its size and sha256. A unit key or section name that systemd does not define is withheld with its length. A `contains` expression that does not finish, or that outlasts `max_seconds`, stops the inventory as partial.

Shows: scheduled jobs the tool listed, with file, line and mode. Does not show: that a job ran or when, or anything in the `unsupported` list. Record: file, line, mtime, mode, the `unsupported` items and how you checked them.

Sensitive output: cron commands and environment values can hold secrets. `cron_dump` answers without that text; it is read from the file written by `write_text: true` in a job run with `secret_output: true`. Cite file and line, never the value or a hash of it.
