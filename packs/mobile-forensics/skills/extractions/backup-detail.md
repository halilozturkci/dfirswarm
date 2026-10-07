---
id: extractions/backup-detail
title: iOS backups and Android .ab files
when: The evidence is an iOS backup directory or an adb backup.
needs: [extractions/what-you-have]
tools: [manifest_db]
requires_host: []
---

Use only if the evidence is an iOS backup directory or an Android adb backup (`.ab`). Not for a file-system extraction.

**iOS backup** (`manifest_db` on the directory):
- It lists the map: file id, domain, relative path, kind, metadata, and whether the blob is present, missing, a directory, a link, or refused (an id that is not 40 hex digits is never joined to a path). The listing is not the phone's file system. Cite relative path, domain, file id and the Manifest.db row.
- **Encryption** is `encrypted`, `not_encrypted` or `unknown`, from `Manifest.plist`. `unknown` (`Manifest.plist` missing, unreadable or without `IsEncrypted`) is not unencrypted. An encrypted backup is not empty: its `Manifest.db` is listed if it opens as SQLite, otherwise the answer says the listing is unavailable. Which parts of an encrypted backup are readable depends on the build that made it: the answer says whether `Manifest.db` opened. No decryption is provided: say what could not be read.
- The key bag and manifest key are reported as present with a length, never printed.
- **Times** are counted from the epoch you pass (`epoch`: `unix` default, or `apple`). The tool does not guess: check against a file whose time the case documents. The wrong epoch is a 31-year shift: `epoch.consistency` counts the times after the backup's date or before 2007; rerun with the other epoch and compare, then say which you kept.
- `completion` is `finished`, `not_finished` or `unknown`, from `Status.plist` `SnapshotState` (`not_finished` makes the status partial; an iTunes backup has no `Status.plist`: `unknown`). `Info.plist` gives the device. A -wal or -journal beside `Manifest.db` is applied in a working copy, never in place.
- A file id is a locator, not a digest of the content. A missing blob limits what you can cite; it does not make the others unusable.

**Android `.ab`** (`android-backup` recipe): the header gives the version and the encryption scheme. An unencrypted payload of version 1 to 5 is listed member by member, without extraction; `coverage.json` says whether the zlib stream and the tar's end block were reached (`payload_stream`, `tar_end`), or the decompression budget stopped it. An encrypted payload (`AES-256`) is header only: no password is read. Apps opt out of backup, so a complete member list is not a complete phone.

Shows: a map of the backup (domain, path, file id, metadata, blob state), its encryption flag, completion state and the backup date its plists record (the computer's clock), and an `.ab`'s header and member names.

Does not show: what the user chose to back up, that a file time in it is when the backup was made (it is the file's time on the device), or anything inside an encrypted payload.

Record: encryption state with its basis, what was readable, the epoch you chose and how you checked it, the completion state, any blob missing.

Sensitive output: none of these reads prints a secret; a job that decrypts or reads keychain content, when you are given a way to, runs with `secret_output: true`.
