---
id: volumes/luks-filevault
title: Choosing the LUKS or FileVault examination route
when: A Linux or Apple volume appears encrypted.
needs: []
card: Identify the format before choosing a reader: crypto_id ({"path": "<image>", "offset": <bytes>}) gives a lead, with its next reader. LUKS and FileVault are different routes with different limits: for a LUKS volume or header read volumes/luks, for an Apple volume volumes/filevault-apfs. Keep the original encrypted object and its metadata as they came. Use material the case supplies, within the recorded authority; jobs that handle secret material run with secret_output: true. If contents stay inaccessible, state exactly which were not examined; do not write that no usable key exists. Does not show: who added an unlock path or when.
tools: [crypto_id]
requires_host: []
---

Use when a Linux or Apple volume appears encrypted and you choose the route. Not for the detail of either route.

LUKS and FileVault are different routes with different limits. Identify the format
before choosing a reader (`crypto_id` gives a lead, with its next reader), and keep
the original encrypted object and its metadata as they came.

Only for a LUKS volume or header (keyslots, metadata copies, detached headers, header
backups): `volumes/luks`.

Only for an Apple volume (Core Storage or APFS): `volumes/filevault-apfs`.

**Does not show.** That either route's reader supports the other's layout; who added an unlock path or when; that a failed route means no usable key exists.

**Sensitive output.** `crypto_id` prints no raw bytes of the file, so a possible key file is never shown; the two second-level notes say what their readers print.

**Both routes.** Use material the case supplies, within the recorded authority. Jobs
that handle secret material run with `secret_output: true`; the ledger and the report
carry source locators, non-secret identifiers, sealed references and results, never
a value, a fragment or a hash. If contents stay inaccessible, state the format
observed, the metadata examined, the material available, the reader's limits, what
you asked for, and exactly which contents were not examined. Do not write that no
usable key exists.
