---
id: persistence/mechanisms
title: Where something arranges to run again
when: You have a payload and need to know how it survives a reboot, or you are sweeping for one.
needs: [artifacts/plists]
tools: [plist_read]
requires_host: []
---

Sweep these in order. The first two carry most real cases on this platform.

**Launch daemons and agents.** Property lists naming a program and when to run
it. A daemon runs as root at boot; an agent runs as the user at login.

    /Library/LaunchDaemons/      root, at boot, machine-wide
    /Library/LaunchAgents/       each user, at login, machine-wide
    ~/Library/LaunchAgents/      that user only, and writable without admin rights
    /System/Library/Launch*/     Apple's own; on a sealed system volume, unwritable

Read `Label`, `ProgramArguments`, `RunAtLoad`, `KeepAlive` and
`StartInterval`. The shape to look for is a label that impersonates an Apple
identifier — `com.apple.something` outside `/System` — pointing at a binary in
`/tmp`, `/Users/Shared`, or a hidden directory. Check each file's own
modification time against its neighbours.

**Login items.** `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`
and newer background-task registrations are typically keyed archives rather
than ordinary semantic plists. `plist_read` can expose the archive structure
but does not resolve every object reference into a trustworthy login-item list;
use a version-aware parser before attributing an item. The System Settings list
a user sees is not necessarily the whole set.

Then the quieter ones: a `cron` table, which still works; `/etc/periodic/`;
a `~/.zshrc` or `~/.bash_profile` line; `emond` rules on older systems; a
configuration profile under `/var/db/ConfigurationProfiles/`, which is how a
managed Mac is legitimately controlled and therefore a good place to hide; a
kernel extension in `/Library/Extensions/`; and a system extension, which on a
modern machine needs user approval and therefore leaves a TCC record.

**Check what was approved, not only what exists.** `/Library/Application
Support/com.apple.TCC/TCC.db` and the per-user copy record which application
was granted screen recording, accessibility, full disk access or the microphone,
and when. An unexpected grant of accessibility is the macOS equivalent of a
service running as SYSTEM, and it is a database a first pass usually walks past.
