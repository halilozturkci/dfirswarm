---
id: extractions/what-you-have
title: Mobile extraction scope and authority
when: Start here: a phone, backup or app export, before any question.
needs: []
tools: [manifest_db, backup_materialise, ab_layout, heic_inspect, file_type]
requires_host: []
---

Use when the evidence is a phone, a backup or an app export and you have not yet said what it can answer. Not for parsing artefacts (`ios/artifacts`, `android/artifacts`).

**Record first** (`evidence/verify`, `evidence/collections`): who supplied it, acquisition tool and version, device model, OS build, acquisition time and clock, container digest, the acquisition log, missing segments. A supplied extraction does not authorise another device, a cloud account or a change to the phone: unclear scope goes to the operator.

**Name the kind from the record and the contents** (`file_type`, the recipe catalogues), not from the label:
- full file system: the files the method could read. Not every file, protection class or plaintext app database, and no device free space unless the record says so.
- logical or backup: what the interface exposed under its policies; list the included and excluded classes from the record.
- "advanced logical", "physical": vendor words; ask for the component methods. Physical bytes can be ciphertext.
- app export: the app's own selection, often without database structure, deleted records or full attachment data.

**Deletion.** A logical extraction has no device free space, but a database in it can hold deleted records in its own free pages and journals (`apps/databases`). Answer a deletion question only from the sources you hold, and name the ones you do not.

**Protection state.** Take lock state and keys from the operator, not from a label. A locked profile, an unacquired one or an encrypted blob is a coverage gap, never an empty source. For an iOS backup or an Android `.ab`, `manifest_db` and the `android-backup` recipe read the plain parts and say what is encrypted: fetch `extractions/backup-detail`. `backup_materialise` lays an unencrypted iOS backup out by its map as a derivative (a copy, not the phone); its `copy_content` is a secret-output job. No decryption is provided here; do not guess at a password.

**Recipes.** iOS tar: the `ios-filesystem` catalogue first (its `sqlite.tsv` finds databases by file name suffix, with their `-wal`, `-shm` and `-journal`; a database with another name is not listed). `ios-ileapp` and `android-aleapp` are run by the kickoff: read their `modules.tsv`. `android-backup-apps` lays an unencrypted `.ab` out and runs ALEAPP on that derivative of an adb backup (not the phone): read `ab-members.tsv` and `modules.tsv`. `ab_layout` makes an unencrypted `.ab` a derivative, never an acquisition. `heic_inspect` previews a HEIC original and walks its boxes; its metadata is the original's. A finished inventory is not a finished examination.

Shows: the acquisition method, its stated scope, the files it could read and what the record says it excluded.

Does not show: that the extraction is the whole device, who used it, or that a listed path holds records.

Record: kind, what it cannot hold, protection state, each source unreadable and why.

Sensitive output: a job over a keychain, an account or a message store runs with `secret_output: true`; write where a secret sits and what it grants, never its value or a hash.
