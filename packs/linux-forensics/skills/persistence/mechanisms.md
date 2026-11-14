---
id: persistence/mechanisms
title: Persistence examination and bounded coverage
when: Finding configured execution mechanisms and separating presence from observed execution.
needs: []
card: Keep apart: present, effective configuration, activation route, evidence it ran. linux_persistence {"root": "<extracted root>"}: execution is not_attempted without execution_rows, and the effective state is never resolved. linux_triage's persistence family is cronjobs and services only. shell_history and cron_dump corroborate; they prove no run. Does not show: that it ran, or who added it.
tools: [cron_dump, linux_persistence, linux_triage, shell_history]
requires_host: []
---

Use when you sweep a Linux host for what is arranged to run. Not for cron and timers (`persistence/cron-timers`, only if the sweep reaches them, read with `cron_dump`) or for shell, login and other quieter routes (`persistence/quieter-routes`, only if the sweep reaches them).

For every candidate keep four things apart: it is present; its effective configuration; the route that would activate it (enablement, a trigger, a schedule, a login); and evidence that it ran. A file shows the first at most. Sweep the mechanisms below in order, record each path and its source, and keep each hit a candidate until its trigger and the object it names are established.

**systemd.** Load paths, drop-ins, aliases, masks, links, generators, transient units and lingering decide what is in effect, and `[Install]` metadata does not show a unit was enabled or started: `persistence/systemd` holds those rules. `linux_persistence` lists the units, `rc.local`, `init.d` and autostart entries with file, line and byte offset; its `execution` is `not_attempted` unless you pass journal rows and its effective state is always unresolved. Resolve the executable, arguments, environment files and conditions without starting anything. A unit named like a distribution component whose `ExecStart` is outside `/usr/bin` and `/usr/sbin`, or one modified recently, is a lead, not proof of unauthorised persistence.

**What wrote or ran it.** Histories (`shell_history`) and `linux_triage`'s `persistence` family (it selects `cronjobs` and `services` only; read each function's status) may show how a mechanism was made or that something started it. They are corroboration for a candidate, and a history line is not proof the command ran.

**Bounded negative.** The supportable result of a sweep that finds nothing is: "No candidate matching these mechanisms was identified in these sources over this period." Record the paths, accounts, namespaces, runtime state, parser limits and excluded mechanisms. It does not show that persistence was absent, how access would be regained, or what anyone intended.

Shows: what is configured to run. Does not show: that a mechanism ran, that it was added during the incident, or who added it. Record: each path and source, the sweep's scope, accounts and namespaces covered, the mechanisms excluded.

Sensitive output: cron commands, environment values, unit `Environment=` lines and history commands can hold secrets. `cron_dump`, `linux_persistence` and `shell_history` answer without that text; the text is read from the file written by `write_text: true` or `write_commands: true` in a job run with `secret_output: true`. Cite file and line, never the value or a hash of it.
