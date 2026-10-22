---
id: persistence/cron-timers
title: cron tables and systemd timers
when: Inventorying scheduled jobs with cron_dump and reading what it did not read.
needs: []
tools: [cron_dump]
requires_host: []
---

Use only if the sweep reaches cron or systemd timers. Not for units and the sweep's frame (`persistence/mechanisms`).

`cron_dump` is a candidate inventory, not a scheduler: it lists `/etc/crontab`, `/etc/cron.d`, the cron.hourly to monthly directories, the Debian-style and Red Hat-style user spools and systemd timers (system, user and each account's own directories), each with its file, line, modification time and mode, and it names what it did not read (`unsupported`: at jobs, anacron, `.service` ExecStart, drop-in merging). It looks in the generator and runtime unit directories under `run/` too, but an acquired disk image holds them only where `/run` was captured, so an empty result there is not a negative. Check what it names as unread by hand, and validate run-parts selection and execute permission, which scheduler was installed, and time zone and daylight-saving behaviour. An `@reboot` entry is a trigger at the cron daemon's start, and a timer with `OnBootSec` counts from boot: neither is a calendar time, and neither shows that the job ran or when. A listed job is not shown to have run. A timer's row shows its first 50 assignments (`assignment_count`, `assignments_not_shown`); the rest are in `pages.assignments`, and `write_text: true` in a job keeps every assignment as a row of its own. A table line whose first word after the schedule is not shaped like a user name, or whose month or weekday field is not a schedule, is `unparsed` (its text is in the text file) and keeps the status partial. A `contains` expression that does not finish stops the inventory as partial.

Shows: scheduled jobs the tool listed, with file, line and mode. Does not show: that a job ran or when, or anything in the `unsupported` list. Record: file, line, mtime, mode, the `unsupported` items and how you checked them.

Sensitive output: cron commands and environment values can hold secrets. `cron_dump` answers without that text; it is read from the file written by `write_text: true` in a job run with `secret_output: true`. Cite file and line, never the value or a hash of it.
