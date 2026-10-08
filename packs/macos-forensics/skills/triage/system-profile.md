---
id: triage/system-profile
title: Build the system profile before anything else
when: Establish the acquisition, OS build, hardware evidence, clocks and acquired volumes.
needs: [evidence/imaging]
tools: [plist_read]
requires_host: [mac_apt.py]
---

Record the acquisition first: a physical image, an APFS container or volume, a
mounted read-only extraction, or a selected-file collection; when it was taken;
collection errors; whether extended attributes and metadata were preserved; which
users, volumes and snapshots are in it. A set of files is not a volume, and
everything below is true of what was acquired.

The profile is a handful of files, most of them property lists (binary: read them
with `plist_read`, see `artifacts/plists`).

    /System/Library/CoreServices/SystemVersion.plist      ProductVersion, ProductBuildVersion
    /Library/Preferences/SystemConfiguration/preferences.plist   recorded host and network configuration
    /Library/Preferences/com.apple.TimeMachine.plist      backup configuration
    /Library/Preferences/.GlobalPreferences.plist         locale and language preferences (each user has one)
    /private/var/db/dslocal/nodes/Default/users/*.plist   local accounts, secret-bearing: see below
    /var/db/.AppleSetupDone                               a setup marker, not a property list

Tie each result to the volume or snapshot it came from: another installed system,
or a snapshot, may carry a different build. The build key is `ProductBuildVersion`
(there is no `BuildVersion`). `.AppleSetupDone` is a lead for the setup date,
through its file times; it is not a record of installation. A configuration value
shows what was stored, not that a connection or a backup happened.

**Accounts.** Enumerate them from the dslocal directory with `plist_read`, naming
the keys the question needs (`key`: `uid`, `generateduid`, `home`, `shell`). An
account plist carries a password verifier; reading a whole one is a job with
`secret_output: true` (`accounts/users`). **Sensitive output:** record that a
verifier is present, where and how long, never its bytes or a hash of them.

**Time.** `/etc/localtime` is a symlink into `/usr/share/zoneinfo/<Region>/<City>`:
record its target as a link, without resolving it against the examiner's
filesystem. Use that zone only for a value stored as local civil time. An APFS
timestamp (Unix epoch) and a property-list date (Apple epoch) are already UTC-based,
so applying the zone to them shifts them twice. The zone found at acquisition need
not be the zone of an earlier event: check its history for the date before
converting a past local time. Keep the raw value, its unit and epoch, and the
uncertainty (`timeline/clocks` if the base pack carries it).

**Hardware.** Distinguish Intel without a T2 chip, Intel with one, and Apple
silicon when the evidence says so. A universal executable does not say which Mac
ran it, and the worker's architecture is a separate fact from the subject's.
Hardware identifiers appear in SystemConfiguration preferences, cached system
reports, logs and Spotlight metadata; the live IORegistry is not in a dead image,
and `/var/db/lockdown` holds records of paired iOS devices, not the Mac's identity.
Report a serial number only when its source identifies this Mac.

**Volumes.** List every acquired APFS container, volume, role and volume group
(the System and Data pair is the usual arrangement, not the whole inventory) and
the snapshots that matter, in `filesystem/apfs`. Record the sealed state you
observed, not the one you expect.

**Programs.** This pack declares `mac_apt.py` 1.33.2, pinned and installed in the
amd64 worker image only: its declared arm64 build leaves it out because it stops at
import there, which is a packaging limit and says nothing about the subject's
hardware. Check the run's tool inventory, and read `mac_apt.py -h` for the input
modes and plugin names the installed copy accepts. Its presence does not show that it
supports the subject's macOS build or that a plugin finished; this pack has no wrapper
or skill for it yet, so keep each plugin's own log and output.

**Does not show.** A dead disk holds retained configuration and recorded activity.
It cannot answer for the live IORegistry, processes, connections, unlocked keys or
service state, and running `launchctl`, `diskutil` or `system_profiler` on the
examiner's Mac describes that Mac. Name the runtime evidence you could not have as a
limitation of the profile.
