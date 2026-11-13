---
id: base/router
title: Base notes by question
when: Pick a base note when none is listed, or you cannot choose.
router: true
---

Use when the index shows only this line and you need a base note. Not for a note's own rules; those below hold for every note.

Always
- An empty result names its reading (no hit, not searched, unsupported, failed, no trace expected); a negative says "No evidence of X was found in A", never "X did not happen".
- An AD1: find items in the catalogue's members listing and extract by locator, every segment declared as an input.
- Text read from an image (OCR, a QR code) is a reading: check the characters a conclusion rests on.

Scope and claims
`evidence/scope` what the case lets you answer, using a secret
`evidence/verify` identity, integrity, provenance of an exhibit
`evidence/provenance` digests, hash domains, tracing a result
`evidence/catalog` the catalogue and its revision
`evidence/coverage` before "not found", "none" or "all"
`evidence/tool-validation` trusting a new parser's negative
`reporting/citations` recording a claim, the report
`reporting/disagreement` a disputed finding

Opening the source
`evidence/imaging` find the volume and offset
`filesystem/layers` containers, splits, snapshots; `filesystem/layers-mapping` LVM, APFS
`evidence/collections` copied files, what they hold
`evidence/archives` archive members as files
`evidence/ad1` FTK logical image
`filesystem/encrypted` encryption or damage
`filesystem/encrypted-metadata` BitLocker, LUKS, FileVault headers

Content
`filesystem/extract` a file out of an image
`filesystem/semantics` path, inode, deleted, allocation
`filesystem/carving` residual bytes, carved candidates
`filesystem/scanners` needle and record scans of bytes
`data/sqlite` databases, WAL; `data/sqlite-secrets` secret tables
`data/browser-storage` IndexedDB, Local and Session Storage
`data/documents-media` PDF, Office, images, media

Time
`timeline/build` keeping timestamp meaning
`timeline/clocks` epochs, zones; `timeline/clocks-drift` drift
`timeline/super` machine timeline
`timeline/super-scope` its parsers, zone, export
