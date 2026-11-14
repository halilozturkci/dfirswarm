---
id: base/router
title: Base notes by question
when: Pick a base note when none is listed, or you cannot choose.
router: true
---

Use when the index shows only this line and you need a base note. Not for a note's own rules; those below hold for every note.

Always
- An empty result names its reading (no hit, not searched, unsupported, failed, no trace expected); a negative says "No evidence of X was found in A", never "X did not happen".
- An AD1: list first, extract by locator; name the first segment only.
- Text read from an image is a reading; a confusable character (' `, l I 1, O 0) makes it a candidate set at medium confidence.

Scope and claims
`evidence/scope` what the case allows, using a secret
`evidence/verify` an exhibit's identity and integrity
`evidence/provenance` digests, tracing a result
`evidence/catalog` the catalogue
`evidence/coverage` before "not found", "none" or "all"
`evidence/tool-validation` trusting a new parser's negative
`evidence/first-stage` which file started it
`reporting/citations` recording a claim
`reporting/disagreement` a disputed finding

Opening the source
`evidence/imaging` find the volume and offset
`filesystem/layers` containers, snapshots; `filesystem/layers-mapping` LVM, APFS
`evidence/collections` copied files
`evidence/archives` archive members as files
`evidence/ad1` FTK logical image
`filesystem/encrypted` encryption or damage
`filesystem/encrypted-metadata` BitLocker, LUKS, FileVault headers

Content
`filesystem/extract` a file out of an image
`filesystem/semantics` path, inode, deleted
`filesystem/carving` residual bytes
`filesystem/scanners` needle scans of bytes
`data/sqlite` databases, WAL; `data/sqlite-secrets` secret tables
`data/browser-storage` IndexedDB, Local Storage; `data/http-cache` cached bodies
`data/documents-media` PDF, Office, images, media
`data/qr` QR codes; `data/glyphs` exact characters; `data/video` frames

Time
`timeline/build` keeping timestamp meaning
`timeline/clocks` epochs, zones; `timeline/clocks-drift` drift
`timeline/super` machine timeline
`timeline/super-scope` its parsers, zone
