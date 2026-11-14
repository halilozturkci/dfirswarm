---
id: extractions/backups
title: Local and cloud backups, and what they cover
when: A backup, cloud copy, transfer or app export is the evidence, or is said to hold the data.
needs: [extractions/what-you-have]
card: backup_materialise {"path": "<backup dir>", "domains": ["<domain>"]} and ab_layout make a derivative, not the phone: plan first; copy_content only as a secret_output job. Does not show: the phone's state.
tools: [manifest_db, backup_materialise, ab_layout, backup_decrypt]
requires_host: []
---

Use when you hold a backup, a synced cloud copy, a device-to-device transfer or an app export. Not for a file-system extraction (`extractions/what-you-have`) or for reading a `manifest_db` or `android-backup` answer (`extractions/backup-detail`, only if you read one).

**Which source is this.** Name it before you cite it (version facts as of November 2026, unchecked):
- Finder or iTunes backup: a directory of blobs named by file id, `Manifest.db` as the map, three plists. `manifest_db` reads the map first.
- iCloud backup and data synced to an account: not in that directory, another source with its own authority; never call a local backup an iCloud one.
- Android `.ab` (`adb backup`): the `android-backup` recipe lists it. Auto Backup, a device-to-device transfer and an app's own export hold what the service or app chose, not a file system.

**A backup holds what was chosen.** Apps opt out, a backup can be unfinished (`completion`), blobs can be missing, and a file time is the device's, not the backup's. Say which limits the answer.

**A derivative is a copy, not the phone.** `backup_materialise` (iOS, by the Manifest) and `ab_layout` (adb, by the backup agent's domains) lay a backup out under `$OUT`, each file tied to its Manifest row or tar member. Plan first; `copy_content` writes the content, only as a `secret_output` job. The `android-backup-apps` recipe lays an unencrypted `.ab` out and runs ALEAPP on it. `ios-ileapp` runs iLEAPP (`-t itunes`) on an unencrypted backup itself, not a derivative; an encrypted one is `failed`. `ab_layout`'s domain table is unchecked against the Android source: report an unknown domain.

**Encrypted backups.** An encrypted iOS backup or `.ab` payload is a coverage gap, not an empty source. For iOS, `backup_decrypt` (library `iphone-backup-decrypt`; a secret-output job) takes `password_ref`, a 0600 file the operator supplies under their authority; never a password in an argument or a note. `verified` means the Manifest opens and each length is its `Size`, not that content is the phone's; `wrong_secret` may be the key bag. An `.ab` payload is not decrypted: record what was not read.

**Decryption provenance.** Record who decrypted a copy, with what, when, and the encrypted original's digest. A copy whose `Manifest.plist` still says encrypted holds ciphertext under plain names: the tools refuse it.

Shows: which backup or copy you hold, what it kept, and a derivative tied to its source rows.

Does not show: the phone's full state, deleted files, activity after the backup, or an encrypted payload's content.

Record: source kind, version, date, completion, encryption, what is missing, the derivative's tool, version and plan or copy.

Sensitive output: a derivative holds the user's data; keep it in the job that made it. Key material and recovery-password-shaped names are withheld from every answer.
