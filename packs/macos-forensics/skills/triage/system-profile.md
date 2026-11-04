---
id: triage/system-profile
title: Build the system profile before anything else
when: Establish the acquisition, OS build, hardware evidence, clocks and acquired volumes.
needs: []
tools: [plist_read, macos_triage]
requires_host: [mac_apt.py]
---

Use when you establish what was acquired and which build and volumes it holds, before any artefact. Not for local-time conversion or hardware generation (`triage/clocks-hardware`, only if needed) or how the image was taken (base pack `evidence/imaging`).

Record the acquisition first: a physical image, an APFS container or volume, a mounted read-only extraction, or a selected-file collection; when it was taken; collection errors; whether extended attributes and metadata were kept; which users, volumes and snapshots are in it. A set of files is not a volume; all below holds of what was acquired.

The profile is a handful of files, most of them property lists (binary: read them with `plist_read`, see `artifacts/plists`).

    /System/Library/CoreServices/SystemVersion.plist      ProductVersion, ProductBuildVersion
    /Library/Preferences/SystemConfiguration/preferences.plist   recorded host and network configuration
    /Library/Preferences/com.apple.TimeMachine.plist      backup configuration
    /Library/Preferences/.GlobalPreferences.plist         locale and language preferences (each user has one)
    /private/var/db/dslocal/nodes/Default/users/*.plist   local accounts, secret-bearing: see below
    /var/db/.AppleSetupDone                               a setup marker, not a property list

Tie each result to the volume or snapshot it came from: another system or a snapshot may carry a different build. The build key is `ProductBuildVersion` (there is no `BuildVersion`). `.AppleSetupDone` is a lead for the setup date, through its file times; it is not a record of installation. A configuration value shows what was stored, not that a connection or a backup happened.

**Accounts.** Enumerate them from the dslocal directory with `plist_read`, selecting keys (`accounts/users`); a whole account plist holds a password verifier and is read only as a job with `secret_output: true`. **Sensitive output:** record that a verifier is present, where and how long, never its bytes or a hash of them.

**Volumes.** List every acquired APFS container, volume, role and volume group (the System and Data pair is the usual arrangement, not the whole inventory) and the snapshots that matter (`filesystem/apfs`). Record the sealed state you observed, not the one you expect.

**Programs.** This pack declares `mac_apt.py` 1.33.2, pinned, in the amd64 worker image only: the arm64 build leaves it out because it stops at import there, a packaging limit that says nothing about the subject's hardware. Check the tool inventory; `macos_triage` runs it and reads its log per plugin; `mac_apt.py -h` prints its input modes and plugin names. Presence shows neither support for the subject's macOS build nor that a plugin finished; its log does. Keep each plugin's log.

**Does not show.** A dead disk holds retained configuration and recorded activity. It cannot answer for the live IORegistry, processes, connections, unlocked keys or service state, and running `launchctl`, `diskutil` or `system_profiler` on the examiner's Mac describes that Mac. Name the runtime evidence you could not have as a limitation of the profile.
