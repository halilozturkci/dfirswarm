---
id: persistence/mechanisms
title: Persistence examination and bounded coverage
when: Finding configured execution mechanisms and separating presence, activation and observed execution.
needs: [triage/system-profile]
tools: [cron_dump, shell_history, linux_triage]
requires_host: []
---

For every candidate keep four things apart: it is present; its effective configuration; the route that
would activate it (enablement, a trigger, a schedule, a login); and evidence that it ran. A file shows the first
at most. Sweep the mechanisms below in order, record each path and its source, and keep each hit a candidate
until its trigger and the object it names are established.

**systemd.** Unit files sit in system and user load paths (`/etc/systemd/system`, `/usr/lib/systemd/system`,
`~/.config/systemd/user` and others); drop-ins, aliases, masks, dependency links, generators, transient and
runtime units and user lingering all change what is in effect. `[Install]` and `WantedBy` supply installation
metadata: they do not show the unit was enabled or started, and enablement shows as links the evidence may or
may not hold. Resolve the executable, arguments, environment files and conditions without starting anything.
A unit named like a distribution component whose `ExecStart` is outside `/usr/bin` and `/usr/sbin`, or one
modified recently, is a lead, not proof of unauthorised persistence.

**cron and timers.** `cron_dump` is a candidate inventory, not a scheduler: it lists `/etc/crontab`,
`/etc/cron.d`, the cron.hourly to monthly directories, the Debian-style and Red Hat-style user spools and
systemd timers (system, user and each account's own directories), each with its file, line, modification time
and mode, and it names what it did not read (`unsupported`: at jobs, anacron, `.service` ExecStart,
generator output, drop-in merging). Check what it names as unread by hand, and validate run-parts selection and
execute permission, which scheduler was installed, and time zone and daylight-saving behaviour. An `@reboot`
entry, or a timer with `OnBootSec`, starts from boot rather than on a calendar. A listed job is not shown to
have run.

**Shell and login scripts, and the quieter routes.** Read startup files by the shell and the login or
interactive mode that applies (`/etc/profile`, `/etc/profile.d/*`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`,
`~/.zshrc`); the file's modification time does not date one line in it. Then SSH authorization and forced
`command=` options, PAM configuration and module files, `/etc/ld.so.preload` and loader configuration, file
capabilities and SUID or SGID files, module-loading configuration and the modules it names, initramfs and boot
artefacts, udev rules, `/etc/rc.local`, container restart policies and application startup hooks. For SUID and
SGID, take modes from the image's file listing, or search an extracted tree by naming its root (never `/`, which
in a worker is the worker's own filesystem); modes in an extracted tree are only as good as the extraction.
Offline there is no `crontab -l`: read the spool file itself.

**What wrote or ran it.** Histories (`shell_history`) and `linux_triage`'s `persistence` family (it selects
`cronjobs` and `services` only; read each function's status) may show how a mechanism was made or that something
started it. They are corroboration for a candidate, and a history line is not proof the command ran.

**Bounded negative.** The supportable result of a sweep that finds nothing is: "No candidate matching these
mechanisms was identified in these sources over this period." Record the paths, accounts, namespaces, runtime
state, parser limits and excluded mechanisms. It does not show that persistence was absent, how access would be
regained, or what anyone intended.

**Does not show.** That a mechanism ran, that it was added during the incident, or who added it.

**Sensitive output.** Cron commands, environment values, unit `Environment=` lines and history commands can
hold secrets. `cron_dump` and `shell_history` answer without that text; the text is read from the file written
by `write_text: true` or `write_commands: true` in a job run with `secret_output: true`. Cite file and line,
never the value or a hash of it.
