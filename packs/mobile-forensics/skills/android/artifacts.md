---
id: android/artifacts
title: Android, and where each answer lives
when: The extraction came from an Android device.
needs: [extractions/what-you-have]
tools: [sqlite_freespace, protobuf_peek]
requires_host: [aleapp]
---

    /data/data/<package>/databases/       that app's own SQLite files
    /data/data/<package>/shared_prefs/    its settings, as XML
    /data/system/packages.xml             every package, its UID, its permissions
    /data/system/users/0/                 accounts, and when the user was created
    /data/system/usagestats/              what ran and for how long, by day
    /data/misc/wifi/ or WifiConfigStore.xml   networks joined
    /data/system_ce/0/accounts_ce.db      accounts with their types
    /sdcard/ or /storage/emulated/0/      shared storage: photos, downloads
    /data/log/, /data/anr/                logs and application-not-responding traces

**`packages.xml` is the first file to read.** It gives the installed packages,
their install and update times, the installer that put each one there, and the
granted permissions. A package sideloaded rather than installed from a store has
a different installer field, and that single value is often the finding.

Start the parser only after identifying the extraction root, and preserve its
stdout beside the report tree:

    mkdir -p work/<agent>/aleapp
    aleapp -t fs -i /absolute/path/to/android-root -o work/<agent>/aleapp

For a tar use `-t tar`. ALEAPP's HTML is a view of its generated data, not the
custody record; keep the structured exports and the exact source paths too.

**`usagestats` is the closest Android has to an execution record.** It is
per-day, protobuf on modern versions, and it says which package was in the
foreground and for how long. `protobuf_peek` reads the blobs without a schema.

**Permissions are the capability list.** An application holding
`READ_SMS`, `ACCESS_FINE_LOCATION` and `SYSTEM_ALERT_WINDOW` together is either
a legitimate messenger or the thing you are looking for, and the installer field
usually decides which.

**Most app data is SQLite with a WAL beside it.** Copy the `-wal` and `-shm`
with the database or you will read a state that is minutes to weeks old. The
most recent messages are the ones in the WAL, which is exactly the set a case
cares about.

Deleted bytes may survive in free pages until reuse, unless secure deletion,
vacuuming or application-level encryption removed their evidential value.
`sqlite_freespace` recovers readable fragments, with the same caution as
everywhere: no reliable time, no guaranteed row boundary, and say so.
