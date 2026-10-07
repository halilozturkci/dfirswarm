---
id: ios/artifacts
title: iOS artefacts by build and source
when: The evidence holds iPhone or iPad application or system data.
needs: [extractions/what-you-have]
tools: [manifest_db, sqlite_query, sqlite_freespace, plist_read]
requires_host: [ileapp, exiftool]
---

Use when the evidence holds iPhone or iPad application or system data. Not for one stream's detail (`ios/biome-segb`, `ios/unified-logs`) or for where the device was (`location/sources`).

**Record** the model, exact OS build, acquisition method, protection state and app versions. Name the build the evidence carries (iOS 17, 18, 26 ...); do not assume a schema for a version you have not seen. Check each path and table in the acquisition.

**Discovery candidates** in a file-system extraction (a backup is resolved through `manifest_db`, never assumed to hold paths): `mobile/Library/SMS/sms.db` (messages), `CallHistoryDB/`, `AddressBook/`, `Safari/`, `Caches/com.apple.routined/` (cache tables: not every row is a significant location), `CoreDuet/Knowledge/` and `Biome/` (activity), `private/var/db/diagnostics/` with `uuidtext/` (logs), `private/var/Keychains/` (protected), `PhotoData/Photos.sqlite`, `Containers/Data/Application/` and `Containers/Shared/AppGroup/` (app data).

**Broad pass.** Start from the `ios-filesystem` catalogue and the `ios-ileapp` generation (`modules.tsv`: `completed` is not "everything parsed"; `no_record` is not "absent"; `errors_logged`, `errored` and `unknown` are gaps). Without a generation, in a job: `ileapp -t tar -i <extraction.tar> -o "$OUT/ileapp"` (`-t fs` for a directory, after `ileapp -h`). Keep stdout, stderr and the report tree. Check any material row against the underlying record.

**Messages.** Query a working copy with `sqlite_query`. Check the schema and joins before assigning participants, direction, thread, transport, edit, deletion or delivery. Synced or local storage does not give authorship. Where the build carries more than one transport (SMS, iMessage, RCS), name which; check the version.

**Deleted messages**: follow `apps/databases` first (`sqlite_freespace`); nothing here promises them.

**Keychain**: metadata is visible, secrets are wrapped by class keys. Record the protection class and what stayed unreadable.

Shows: what a parser read from a source in this acquisition, and the record that source holds.

Does not show: a person's actions, that a cache row is a visit, or an application's identity from a container name alone: `ios/containers-and-time` only if you must attribute a container or convert a time.

Record: build, source path with acquisition locator, parser and version, raw value beside every conversion.

Sensitive output: message, keychain and account stores run as a job with `secret_output: true`; `plist_read` prints binary values in some installed versions as a size and a preview: check before running it on a plist that can hold a key or verifier. For photos, `exiftool -json -n -- FILE` on the exact file; read `location/sources` before any location claim.
