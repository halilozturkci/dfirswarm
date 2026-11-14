# Skills in this pack

Fetch a body with `skill("<id>")`. A body may name others; fetch those the same way.

Router: `base/router`

Core: `evidence/ad1`, `data/documents-media`, `evidence/coverage`

- `base/router` Base notes by question: Pick a base note when none is listed, or you cannot choose.
- `data/browser-storage` Browser storage in LevelDB and IndexedDB: IndexedDB, Local or Session Storage of a Chromium or Electron app.
- `data/documents-media` Document and image content is its own layer: A PDF, Office file, image or media file holds the evidence.
- `data/glyphs` Exact characters: Text read off a picture must be exact.
- `data/http-cache` HTTP cache bodies: A file a Chromium browser cached is needed.
- `data/qr` QR symbols: A QR code in a picture, damaged or in pieces.
- `data/sqlite` A SQLite database is a set of files: A SQLite database, with or without its -wal, -shm or -journal.
- `data/sqlite-secrets` Secret tables without the values: A table holds cookies, logins, tokens or keys.
- `data/video` Every frame of a video: A video shows it briefly, or will not open.
- `evidence/ad1` An AD1 image is a collection in a container: Evidence is an FTK Imager logical image (.ad1).
- `evidence/archives` Archives and extraction fidelity: A zip, tar, 7z, RAR or compressed file whose members you need as files.
- `evidence/catalog` Use the catalogue with coverage and revision: At the start, or before reporting a catalogue search.
- `evidence/collections` What a logical collection contains: Evidence arrives as copied files, an archive or an AD1 logical image.
- `evidence/coverage` What a search did and did not cover: Before writing "not found", "none" or "all".
- `evidence/first-stage` First-stage candidates: Which file started it on one machine.
- `evidence/imaging` Find the volume and its offset: Before listing a disk or volume, or diagnosing an unreadable source.
- `evidence/provenance` Hash domains and the provenance chain: Quoting or comparing a digest, or tracing a result to an exhibit.
- `evidence/scope` What the examination may answer: At the start, or before widening a search or using a secret.
- `evidence/tool-validation` Validate a parser before trusting its result: A negative or decisive value rests on a tool's output, or the tool is new.
- `evidence/verify` Establish evidence identity, integrity and provenance: Before examination, after an integrity concern, before reporting.
- `filesystem/carving` Recover candidate structures and validate their limits: Data is outside a readable file, or only residual bytes.
- `filesystem/encrypted` Tell encryption from other causes of unreadability: A reader cannot open a source, or validated metadata identifies encryption.
- `filesystem/encrypted-metadata` Encryption metadata, protectors and keys: A header identifies BitLocker, LUKS or FileVault.
- `filesystem/extract` Get a file out of an image and name its record: You need the bytes of something the listing names.
- `filesystem/layers` Layered storage and historical states: A container, split set, volume manager or snapshot is between you and files.
- `filesystem/layers-mapping` Mapping layers and APFS: mmls names the slot but fsstat cannot read it.
- `filesystem/scanners` Needle and feature scans over raw bytes: Searching raw bytes for strings or record types.
- `filesystem/semantics` Filesystem identity, allocation and recovery limits: Citing a file by path or inode, reading a deleted entry, or saying it was deleted.
- `reporting/citations` Connect each answer to inspectable evidence and its limits: Recording a claim, reviewing an answer, or the report.
- `reporting/disagreement` Correct the evidence record and every dependent conclusion: A finding is disputed, or new evidence changes a reviewed result.
- `timeline/build` Preserve timestamp meaning and uncertainty: Before interpreting or combining dated observations.
- `timeline/clocks` Timestamp semantics, zones and clock uncertainty: Before a number becomes a time in the ledger, or sources disagree.
- `timeline/clocks-drift` Clock changes, drift and NTFS time sets: Clocks may be set or drift, or NTFS times disagree.
- `timeline/super` Build and validate a scoped machine timeline: Broad parser output can find events or widen coverage.
- `timeline/super-scope` Parsers, zone and export for a Plaso timeline: Choosing parsers, a zone, or another export.
