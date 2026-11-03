---
id: extractions/backups
title: Local and cloud backups, and what they cover
when: A backup, cloud copy, transfer or app export is the evidence, or is said to hold the data.
needs: [extractions/what-you-have]
tools: [manifest_db, backup_materialise, ab_layout]
requires_host: []
---

Use when a backup, a synced cloud copy, a device-to-device transfer or an app export is what you hold. Not for a file-system extraction (`extractions/what-you-have`), and not for how to read a `manifest_db` or `android-backup` answer (`extractions/backup-detail`, only if you read one).

**Which source is this.** Name it before you cite it (version facts as of November 2026, not checked against a fixture):
- Finder or iTunes backup: a directory of blobs named by file id, `Manifest.db` as the map, three plists. `manifest_db` reads the map first.
- iCloud backup and data synced to a cloud account: not in that directory. What the account holds is another source with its own authority; never call a local backup an iCloud one.
- Android `.ab` (`adb backup`): the `android-backup` recipe lists it. Auto Backup, a device-to-device transfer and an app's own export hold what the service or the app chose to keep, not a file system.

**A backup holds what was chosen.** Apps opt out, a backup can be unfinished (`completion`), blobs can be missing, and a file time is the device's, not the backup's. Say which of these limits the answer.

**A derivative is a copy, not the phone.** `backup_materialise` (iOS, by the Manifest) and `ab_layout` (adb, by the backup agent's domains) lay a backup out under `$OUT`, each file tied to its Manifest row or tar member. Run each as a plan first (no content, no digest); `copy_content` writes what the backup holds and runs only as a job with `secret_output: true`. The `android-backup-apps` recipe lays an unencrypted `.ab` out and runs ALEAPP on it. The domain table behind `ab_layout` is not checked against the Android source: if a domain is listed as unknown, say so.

**Encrypted backups.** An encrypted iOS backup or `.ab` payload is a coverage gap, not an empty source. No decryption is provided here and no tool reads a password: record what could not be read, and ask the operator who holds the secret and under what authority. A password never goes in an argument or a note.

**Decryption provenance.** If a decrypted copy is handed to you, record who decrypted it, with what, when, and the digest of the encrypted original it came from. A copy whose `Manifest.plist` still says it is encrypted has blobs that are ciphertext under plain names: the tools refuse it.

Shows: which backup or copy you hold, what it chose to keep, and a derivative tied to its source rows.

Does not show: the phone's full state, deleted files, activity after the backup, or what is inside an encrypted payload.

Record: source kind, version and date, completion, encryption state, what is missing, the derivative's tool, version and plan or copy.

Sensitive output: a derivative holds the user's data; keep it in the job that made it. Key material and recovery-password-shaped names are withheld from every answer.
