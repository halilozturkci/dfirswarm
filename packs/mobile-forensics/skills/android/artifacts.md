---
id: android/artifacts
title: Android artefacts by build, user and protection state
when: The evidence holds Android application or system data.
needs: [extractions/what-you-have]
tools: [sqlite_query, sqlite_freespace, protobuf_peek]
requires_host: [aleapp]
---

Use when the evidence holds Android application or system data. Not for an adb backup's layout (`extractions/backup-detail`) or for where the device was (`location/sources`).

**Record** the Android version, build fingerprint, security patch level, maker, app versions and every acquired user and profile id. Do not infer coverage from user 0: look for secondary users, work profiles and, where the build supports it, a private space or vendor containers. A credential-encrypted profile that was locked or not acquired is a coverage gap, not an empty profile.

**Discovery candidates** (keep the extraction's own path mapping): `/data/user/<user>/<package>/` (credential-encrypted app storage), `/data/user_de/<user>/<package>/` (device-encrypted), `/data/data/<package>/` (commonly the same as user 0), `/data/system/` and per-user system directories (packages, permissions, accounts, usage; files vary by build), `/data/media/<user>/` (shared storage), Wi-Fi stores, ANR traces, tombstones. List the databases, preferences and files of each app scope.

**Packages.** Read package metadata with each user's installed and enabled state, the requested permissions, the granted ones and any recorded use of them. Installer, initiator, origin and update owner are different things; a missing or non-store value does not show sideloading, and sideloading does not show malice. Corroborate a security finding with observed behaviour and independently attributable data.

**Broad pass.** Use the `android-aleapp` generation first and read its `modules.tsv` (`completed` is not "all parsed"; `no_record` is not "absent"; gaps are `errored`, `errors_logged`, `unknown`). Without one, in a job: `aleapp -t fs -i <android-root> -o "$OUT/aleapp"` (`-t tar` or `-t zip` for those inputs, after `aleapp -h`). Keep stdout, stderr and the report tree; check a material row against its source record.

**Usage data** can hold events and daily, weekly, monthly or yearly aggregates. Identify the build's format, user, event types, interval edges and token mappings before decoding. `protobuf_peek` shows wire fields, not Android meanings. Foreground time is neither a person's action nor a full execution record.

**Messages**: SMS/MMS, RCS and each chat app can use different stores; check each (`sqlite_query` on a working copy, `sqlite_freespace` for free space: `apps/databases`). A notification or cache can corroborate content, not delivery or authorship. Databases and deletion: `apps/databases`.

**Wi-Fi**: a saved configuration shows configuration, not that the phone joined it or where.

Shows: what package, user and app stores record, and what the parsers decoded from them.

Does not show: a person, an intent, or absence beyond the profiles, retention and parser coverage you checked.

Record: version, user, path, parser and version, raw value beside a conversion.

Sensitive output: Wi-Fi, account and message stores run as a job with `secret_output: true`; record where a secret sits, never the value or a hash.
