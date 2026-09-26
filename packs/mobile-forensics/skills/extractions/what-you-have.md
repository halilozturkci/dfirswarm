---
id: extractions/what-you-have
title: What kind of extraction you were handed
when: The evidence is a phone, or something taken off one.
needs: [evidence/collections]
tools: [manifest_db, file_type]
requires_host: []
---

Nothing else in this pack matters until this is settled, because the answer
decides what questions are even askable.

    Full file system        every file the device has, including app sandboxes
                            and the databases that carry deleted rows
    Logical / backup        what the backup protocol exposes: some app data,
                            no system logs, no unallocated space
    Advanced logical        a backup plus what a few agent tricks add
    Physical                a bit-for-bit image. On modern phones, rare to
                            impossible: the storage is encrypted at rest and the
                            keys are in hardware
    An app export           one application's own "download my data"

**A logical extraction cannot answer a question about deletion.** There is no
unallocated space in it, no file slack, and no journal beyond what SQLite itself
carries inside each database. Say that once, plainly, rather than reporting that
nothing was found.

**An iOS backup is not a file tree.** It is a flat directory of files named by a
hash, with `Manifest.db` mapping each hash to the domain and relative path it
came from. `manifest_db` reads that map. Without it the files are unusable;
with it they are a file system.

For an iOS full-file-system tar, inspect the `mobile-forensics/ios-filesystem`
catalogue generation first. It lists the domain artefacts and every SQLite
database with its `-wal`, `-shm` and rollback-journal companions without
extracting the archive. If there is no generation, request that recipe rather
than repeatedly listing the whole tar.

**An encrypted iOS backup is encrypted at the file level**, and the flag is in
`Manifest.plist`. If it is set and nobody has the password, the extraction is
inert: say so and stop, rather than reporting empty databases.

**Android varies by version and by vendor.** `/data/data/<package>` is the app
sandbox, `/data/user/0` is the same thing on a multi-user device, and
`/sdcard` is shared storage with nothing private in it. A "backup" made with
`adb backup` is deprecated, partial, and silently excludes any app that opted
out.

An Android `.ab` begins with `ANDROID BACKUP`, then version, compression and
encryption lines. Use the `mobile-forensics/android-backup` catalogue: an
unencrypted payload is inventoried member by member; an encrypted one is
reported as header-only until its password is supplied. A complete member list
still does not prove completeness because application policy decided what the
backup command was allowed to include.

Record what you were given and by whom, with the hash of the container, before
anything else. See `evidence/verify` in the base pack.
