---
id: triage/clocks-hardware
title: Zone, epochs and hardware generation of the Mac
when: Convert a local time, or say which Mac hardware generation the evidence shows.
needs: []
card: plist_read on SystemConfiguration preferences gives hardware identifiers: report a serial number only when its source identifies this Mac. An APFS time (Unix epoch) and a plist date (Apple epoch) are already UTC-based, so applying the /etc/localtime zone shifts them twice; use it only for local civil time, after checking its history for the date. Does not show: the zone at an earlier event, or the subject's hardware from the worker's.
tools: [plist_read]
requires_host: []
---

Use only if a question turns on a local time or on the hardware generation. Not for the acquisition and build (`triage/system-profile`).

**Time.** `/etc/localtime` is a symlink into `/usr/share/zoneinfo/<Region>/<City>`: record its target as a link, without resolving it against the examiner's filesystem. Use that zone only for a value stored as local civil time. An APFS timestamp (Unix epoch) and a property-list date (Apple epoch) are already UTC-based, so applying the zone to them shifts them twice. The zone found at acquisition need not be the zone of an earlier event: check its history for the date before converting a past local time. Keep the raw value, its unit and epoch, and the uncertainty (`timeline/clocks` if the base pack carries it).

**Hardware.** Distinguish Intel without a T2 chip, Intel with one, and Apple silicon when the evidence says so. A universal executable does not say which Mac ran it, and the worker's architecture is a separate fact from the subject's. Hardware identifiers appear in SystemConfiguration preferences (read with `plist_read`), cached system reports, logs and Spotlight metadata; the live IORegistry is not in a dead image, and `/var/db/lockdown` holds records of paired iOS devices, not the Mac's identity. Report a serial number only when its source identifies this Mac.

Shows: the zone configured at acquisition and the hardware generation the evidence names. Does not show: the zone in force at an earlier event, or the subject's hardware from the worker's.
Record: the symlink target, the source of each hardware identifier, the raw time value with its epoch.
