---
id: persistence/mechanisms
title: Where something arranges to run again
when: Distinguish persistence configuration, registration, enabled state and execution.
needs: [artifacts/plists]
tools: [plist_read]
requires_host: []
---

Keep four things apart: configuration on disk, registration with the system, whether the
item is enabled, and whether it ran. A file can be disabled, orphaned, superseded,
legitimate or never loaded.

**Launch daemons and agents.** Property lists naming a program and when to run it. The
directory sets the domain the job is loaded into; the keys decide who runs it and when.

    /Library/LaunchDaemons/      system domain, machine-wide
    /Library/LaunchAgents/       user domain, machine-wide
    ~/Library/LaunchAgents/      that user only, and writable without admin rights
    /System/Library/Launch*/     Apple's own; normally on the signed System volume

Record the System volume's observed integrity and what the acquisition covered; do not
assume an intact seal. Keep `Label`, `Program`, `ProgramArguments`, `BundleProgram`,
`UserName`, `GroupName`, `RunAtLoad`, `KeepAlive`, `StartInterval`,
`StartCalendarInterval`, `WatchPaths`, `QueueDirectories`, `MachServices`, `Sockets`, the
working directory and the names of the environment variables (their values are sensitive,
below). A system-domain daemon can name a non-root user
and can start on demand; an agent loaded at login has not shown its program ran then.

Resolve the program and what it references inside the acquired filesystem. Do not run
anything, and do not follow an evidence link into the examiner's filesystem. Keep file
identity, original metadata, ownership, permissions, extended attributes and signature
information, and read scripts statically. A familiar label, an Apple-looking identifier
(`com.apple.*` outside `/System`), a writable location (`/tmp`, `/Users/Shared`, a
hidden directory), a valid signature or an odd mtime next to its neighbours is a signal
to follow up, not a verdict.

A plist's `Disabled` value is one input; overrides can be stored elsewhere, and a dead
disk cannot be asked for launchd's current state by running `launchctl` on the
examination host.

**Login and background items.** Read the user's legacy store
(`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`)
and, on newer builds, the registrations under
`/private/var/db/com.apple.backgroundtaskmanagement/` (versioned `BackgroundItems-v*.btm`
where present); also look at services embedded in application bundles and login items
registered through ServiceManagement. Check the stores and their schema against the build
the evidence carries. `plist_read` shows these keyed archives as structure; it does not
give a decoded inventory. Use a version-aware parser and keep item identifier, parent
application, program, user or domain and recorded state. A registration is not
execution, and what System Settings shows now is not a historical inventory.

**The quieter ones.** A `cron` table, `/etc/periodic/`, a line in `~/.zshrc` or
`~/.bash_profile`, `emond` rules on older systems, configuration profiles under
`/var/db/ConfigurationProfiles/`, kernel extensions in `/Library/Extensions/` and system
extensions. Profiles are how a managed Mac is legitimately configured, so compare with
the estate's management baseline and the install and update records before calling any of
them foreign.

**Separate questions.** Approving, loading and holding a privacy permission are different
things. A system extension's approval can be shaped by management policy, and registering
one does not by itself create a privacy-permission record. Privacy permissions are in the
TCC databases (system and per user, with their sidecars), which this pack has no skill for
yet: do not read an Accessibility permission as root or SYSTEM, or a TCC row's modified
time as the time of a grant.

**Sensitive output.** `ProgramArguments` and `EnvironmentVariables` can carry credentials: a
token on a command line, or a variable named for a service and not for a secret (`GITHUB_PAT`
is one), which no key-name pattern in `plist_read` catches, so it prints the value. Read a
launch sweep as a job with `secret_output: true`, treat every argument and environment value
as sensitive, and cite the file and key, never the value.

**Does not show.** Execution, intent or compromise. Report persistence, privacy
authorization and observed execution as three findings, each with what corroborates it
(the unified log, install records, snapshots) and what would disprove it.
