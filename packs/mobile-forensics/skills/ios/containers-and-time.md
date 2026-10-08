---
id: ios/containers-and-time
title: iOS containers and time conversion
when: You must attribute an app container or convert an iOS time.
needs: []
tools: [plist_read, manifest_db, timestamp_decode, sqlite_query]
requires_host: []
---

Use only if you must attribute an app container to an application or convert an iOS time value. Not for choosing sources (`ios/artifacts`).

**Containers.** A `Data/Application/<uuid>` or `Shared/AppGroup/<uuid>` directory name is not an identity. Map it with its `.com.apple.mobile_container_manager.metadata.plist` (read it with `plist_read`), the installation records (`MobileInstallation`) or, in a backup, the domain `manifest_db` lists. App, extension and shared group are different containers. An unmapped uuid limits attribution to an application; the original file and its locator stay citable. A restore or a migration can move data between containers: say which one you hold.

**Times.** Apple absolute time is seconds from 2001-01-01 UTC; Unix seconds appear in older or cross-platform stores; nanoseconds, milliseconds and monotonic clocks occur too. Choose from the field's schema (`sqlite_query` on the table definition and a documented value), never from a date that looks plausible. `timestamp_decode` lists candidate readings under several epochs and does not say which is right; an earlier version dropped fractional seconds, so check the installed one. Keep the raw value and the precision beside any conversion and say which clock and zone.

Shows: which application a container belongs to, where a mapping exists, and a time under a stated epoch.

Does not show: that two stores' times are on one clock, that a converted time is when a person acted, or that a date in the right range is the right epoch.

**Corroborate** a conversion against a value the case documents (an acquisition time, a message with a known send time) in the same store.

Record: raw value, epoch, precision, zone assumption, how you checked it.

Sensitive output: a container's preference or account plists can hold verifiers or tokens: run `plist_read` on them as a job with `secret_output: true`, or read only the keys the question needs.
