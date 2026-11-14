---
id: extractions/backup-detail
title: iOS backups and Android .ab files
when: The evidence is an iOS backup directory or an adb backup.
needs: [extractions/what-you-have]
card: manifest_db {"path": "<backup>", "epoch": "apple"}: encryption unknown is not unencrypted, and an encrypted backup is not empty. epoch is never inferred: a wrong one is a 31-year shift, check it against a documented time. Does not show: anything inside an encrypted payload.
tools: [manifest_db, backup_decrypt]
requires_host: []
---

Use only if you read a `manifest_db` or `android-backup` answer. Not for what a backup covers (`extractions/backups`).

**iOS backup** (`manifest_db` on the directory):
- It lists the map: file id, domain, relative path, kind, metadata, blob state (present, missing, directory, link, refused; an id not 40 hex digits is never joined to a path). Not the phone's file system. Cite relative path, domain, file id, Manifest.db row.
- **Encryption** (`Manifest.plist`): `encrypted`, `not_encrypted` or `unknown` (plist missing, unreadable or without `IsEncrypted`), which is not unencrypted. An encrypted backup is not empty: its `Manifest.db` is listed if it opens as SQLite, else the answer says the listing is unavailable; what is readable depends on the build that made it. Decrypting: `extractions/backups`.
- Key bag and manifest key: a presence and a length. `contains` and `domain` match the path and domain as printed (a recovery-password-shaped or over-long component is withheld). A `file` cell over 1 MiB, NULL or not a keyed archive gives no metadata (partial).
- **Times** are counted from the epoch you pass (`epoch`: `unix` default, or `apple`). Never guessed: check against a file whose time the case documents. A wrong epoch is a 31-year shift (`epoch.consistency` counts times after the backup's date or before 2007): rerun with the other, compare, say which you kept.
- `completion` is `finished`, `not_finished` or `unknown`, from `Status.plist` `SnapshotState` (`not_finished` is partial; an iTunes backup has no `Status.plist`: `unknown`). `Info.plist` has the device. A -wal or -journal beside `Manifest.db` is applied in a working copy, never in place.
- A file id is a locator, not a digest of the content. A missing blob limits what you cite, nothing else.

**Android `.ab`** (`android-backup` recipe): the header gives the version and the encryption scheme. An unencrypted payload of version 1 to 5 is listed, not extracted; `coverage.json` says whether the zlib stream and the tar's two end blocks were reached (`payload_stream`, `tar_end`), or the budget stopped it; a lone zero block or data after the end blocks is said (partial). An encrypted payload (`AES-256`) is header only: no password is read. Apps opt out of backup: a full member list is not a full phone.

Shows: the backup's map, encryption flag, completion state and the backup date its plists record; an `.ab`'s header and member names.

Does not show: what the user chose to back up, when the backup was made (a file time is the device's), or anything inside an encrypted payload.

Record: encryption state and basis, what was readable, the epoch and its check, completion, any blob missing.

Sensitive output: key material is never printed; the plain plists' device identifiers (serial, UDID, IMEI, ICCID, phone number) are. Only `backup_decrypt` decrypts, as a `secret_output: true` job.
