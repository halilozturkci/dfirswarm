---
id: persistence/mechanisms
title: Where something arranges to run again
when: Distinguish persistence configuration, registration, enabled state and execution.
needs: []
card: plist_read on a launch plist: configuration is not registration, enablement or execution. ProgramArguments and EnvironmentVariables can hold credentials it prints: sweep as a job with secret_output: true, cite file and key. Does not show: execution, intent or compromise.
tools: [plist_read]
requires_host: []
---

Use when you sweep a Mac for launch daemons and agents or must separate configuration from execution. Not for login and background items, cron, profiles, extensions or privacy permissions (`persistence/login-items-quieter`, only if the sweep reaches them).

Keep four things apart: configuration on disk, registration with the system, whether the item is enabled, and whether it ran. A file can be disabled, orphaned, superseded, legitimate or never loaded.

**Launch daemons and agents.** Property lists naming a program and when to run it. The directory sets the domain the job is loaded into; the keys decide who runs it and when.

    /Library/LaunchDaemons/      system domain, machine-wide
    /Library/LaunchAgents/       user domain, machine-wide
    ~/Library/LaunchAgents/      that user only, and writable without admin rights
    /System/Library/Launch*/     Apple's own; normally on the signed System volume

Record the System volume's observed integrity and what the acquisition covered; do not assume an intact seal. Keep `Label`, `Program`, `ProgramArguments`, `BundleProgram`, `UserName`, `GroupName`, `RunAtLoad`, `KeepAlive`, `StartInterval`, `StartCalendarInterval`, `WatchPaths`, `QueueDirectories`, `MachServices`, `Sockets`, the working directory and the names of the environment variables (their values are sensitive, below). A system-domain daemon can name a non-root user and can start on demand; an agent loaded at login has not shown its program ran then.

Resolve the program and what it references inside the acquired filesystem. Do not run anything, and do not follow an evidence link into the examiner's filesystem. Keep file identity, original metadata, ownership, permissions, extended attributes and signature information, and read scripts statically. A familiar label, an Apple-looking identifier (`com.apple.*` outside `/System`), a writable location (`/tmp`, `/Users/Shared`, a hidden directory), a valid signature or an odd mtime next to its neighbours is a signal to follow up, not a verdict.

A plist's `Disabled` value is one input; overrides can be stored elsewhere, and a dead disk cannot be asked for launchd's current state by running `launchctl` on the examination host.

**Sensitive output.** `ProgramArguments` and `EnvironmentVariables` can carry credentials: a token on a command line, or a variable named for a service and not for a secret (`GITHUB_PAT` is one), which no key-name pattern in `plist_read` catches, so it prints the value. Read a launch sweep as a job with `secret_output: true`, treat every argument and environment value as sensitive, and cite the file and key, never the value.

**Does not show.** Execution, intent or compromise. Report persistence, privacy authorization and observed execution as three findings, each with what corroborates it (the unified log, install records, snapshots) and what would disprove it.
