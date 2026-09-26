# Mobile Forensics Pack

iOS and Android: what kind of extraction you were handed, what it cannot
contain, and where each answer actually lives.

Depends on the Computer Forensics Base Pack and on the macOS Forensics Pack —
iOS is macOS's sibling, and `plist_read` from that pack is needed for most of
what an iPhone stores.

## What it carries

**Seven skills**: `extractions/what-you-have`, `ios/artifacts`,
`ios/biome-segb`, `ios/unified-logs`, `android/artifacts`, `apps/databases`,
`location/sources`.

**Three tools.** `manifest_db` turns an iOS backup's flat directory of
hash-named files back into a file system, and reports the encryption flag first
— because an encrypted backup returns empty databases rather than failing, and
an examiner who misses that reports an empty phone. `sqlite_freespace` recovers
deleted rows from a database's freelist pages **and its per-page freeblock
chain**, which is where a deleted row's bytes actually sit. `protobuf_peek`
reads a protobuf blob without its schema, for the Android and iOS artefacts that
stopped being SQLite. All three return their complete matching result; the
harness retains oversized stdout rather than letting the tools cut it.

**Two recipes.** `ios-filesystem` turns a full-file-system tar into a structural
mobile catalogue without extracting it. `android-backup` reads an adb-backup
header and inventories every member of an unencrypted payload. Both say exactly
what they did not cover in `coverage.json`.

**One goal template**: `phone-examination.md`.

## The two things this pack will not let you skip

**A logical extraction cannot answer a question about deletion.** No unallocated
space, no slack, nothing outside what the backup protocol exposes. That belongs
in the report as a limit on the evidence.

**Copy the `-wal` with the database.** The newest messages are in the
write-ahead log, not in the `.db`, and on a phone that is never closed cleanly
the checkpointed state can be weeks old. Copying only the `.db` silently loses
exactly the period a case is about.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/macos-forensics
    scripts/pack.sh install packs/mobile-forensics
    scripts/swarm.sh start --pack computer-forensics-base,macos-forensics,mobile-forensics ...
