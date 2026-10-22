# Computer Forensics Base Pack

The method and the tooling every examination needs, whatever the operating
system the evidence came from: work out what you were handed and where the
volume starts, verify the evidence, build a catalogue before spending a token,
extract and carve, tell an encrypted volume from an unreadable one, keep a
timeline that survives a second reader, and write a report whose every claim
cites something checkable.

Platform-specific artefact knowledge lives in the packs that depend on this one.

## What it carries

**Twenty-nine skills**, fetched one at a time by the agents that need them. Each is a leaf of at most 800 tokens that opens with "Use when ... Not for ..."; a topic that needs more has a second-level leaf the first one points to ("only if"), so `skills/INDEX.md` lists both. One of them is the pack's router, `base/router` (at most 400 tokens): when a run's index is over its budget the prompt shows this one line for the pack, and the router names every other skill by the question it answers:

| | |
| --- | --- |
| `base/router` | the pack's router: which note answers which question (shown alone when the run's index is over budget) |
| `evidence/scope` | what the case lets the examination answer: the questions, the premises, the exhibits, and when a missing source becomes an acquisition request |
| `evidence/verify` | establish the evidence's identity, integrity and provenance, and what a hash match does and does not show |
| `evidence/provenance` | hash domains (container, decoded stream, volume, extracted object, transformed output) and the chain from the delivered exhibit to a result; the digest of a secret is never written |
| `evidence/imaging` | the probe, the partition table and the sector offset every command needs |
| `filesystem/layers` | container, backing chain, split set, encryption and snapshot: the address space each offset belongs to |
| `filesystem/layers-mapping` | a logical volume (LVM, dynamic disk, Storage Space, RAID member) or an APFS container: rebuilding the layer under the file system |
| `evidence/catalog` | read the catalogue with its coverage and revision before you spend a token |
| `evidence/coverage` | what a search did and did not cover: no hit, not searched, unsupported, failed, no trace expected; the `kind=coverage` record |
| `evidence/collections` | the evidence is a zip, a directory tree or an AD1, not a disk: what it contains and what it cannot show |
| `evidence/archives` | a zip, tar, 7z or compressed file: list it, extract it under budgets, never recreate a link, keep every name |
| `evidence/ad1` | an FTK Imager logical image: list, extract and corroborate it |
| `evidence/tool-validation` | validate a parser before you trust it: version, status counts, the decisive field against the bytes, independence, a positive control |
| `data/sqlite` | a SQLite database is a set of files: snapshot it, apply its WAL in a copy, query the state you name |
| `data/sqlite-secrets` | a table of cookies, logins, tokens, keys or messages: its values go to a sealed file, never into your context (`sqlite_query` with `write_values`) |
| `data/documents-media` | document and image content as layers: bytes, rendering, extracted text, embedded objects, metadata, OCR, concealment |
| `filesystem/extract` | get a file out of an image, and say which record it came from |
| `filesystem/semantics` | path against object identity, record reuse, sizes, allocation, deletion, times, snapshots and TRIM: what a recovered file does and does not show |
| `filesystem/carving` | recover candidate structures where there is no file system, and say how far to trust them |
| `filesystem/scanners` | needle and feature scans over raw bytes (`ioc_scan`, `chunk_needles`, `feature_scan`) |
| `filesystem/encrypted` | a volume the toolkit cannot read: encryption is one explanation among several |
| `filesystem/encrypted-metadata` | BitLocker, LUKS and FileVault metadata, protectors, and the rules for a key the case supplies |
| `timeline/build` | the ledger's dated facts: the raw value kept, the conversion last |
| `timeline/clocks` | timestamp semantics: epochs, zones and their daylight-saving history, ambiguous local times, resolution |
| `timeline/clocks-drift` | clock changes, drift, monotonic order and the two NTFS time sets |
| `timeline/super` | the window an incident happened in, from evidence too large to read |
| `timeline/super-scope` | parsers, zone and export for a Plaso timeline |
| `reporting/citations` | every claim resolves to an inspectable observation, and a negative is bounded |
| `reporting/disagreement` | disputing, correcting and republishing, through the ledger's own acts |

**Sixteen tools**: `image_layout`, `check_inputs`, `catalog_search`,
`icat_extract`, `sig_carve`, `file_carver`, `ioc_scan`, `chunk_needles`,
`file_type`, `sqlite_query`, `feature_scan`, `timeline_super`,
`timestamp_decode`, `ad1_extract`, `archive_extract`, `sqlite_snapshot`. `file_type` to `timestamp_decode` arrived
with the packs that depend on this one: a tool every pack would have carried
belongs here once, not in each of them. `ad1_extract` writes an AccessData
AD1 logical image's files out, checked against the digests the image
records; run as a job, what it writes is catalogued in turn. `archive_extract`
writes the members of a zip, tar (gzip, bzip2, xz, zstd), 7z or single compressed
file into a private directory under byte, ratio, member, depth and time budgets, and never
recreates a link or a device.
Every one takes JSON on stdin and returns JSON, and every call lands on the
run's trace under the calling agent's name. What they return is bounded and
says so: a carve is a candidate with `boundary: validated` or `heuristic`, a
scan returns locators and not the bytes around a hit (those go to a sealed
file only when a job asks, with `secret_output`), a run that ended part way is
`partial` with the exit codes of its stages, and a count never depends on how
the file was read (`ioc_scan`, `chunk_needles` and `sig_carve` find their matches with one shared engine,
held equal in the three by a test and to a brute-force search over every way of cutting a stream into reads). A tool with a time budget of its own keeps that budget
inside the manifest's limit, so reaching it is reported (`partial`, `not_checked`,
`interrupted`) and is not a kill with nothing said: the scanners (`ioc_scan`,
`chunk_needles`) and `file_carver` have one, and the answer names where to go on or how far it got.
`feature_scan`'s counting of the files bulk_extractor wrote has none. `sqlite_query` reads the main
database file and reports a write-ahead log beside it without applying it; on a table of secrets,
run as a job with `secret_output`, `write_values` with a `table` writes the cells to a 0600 file under `$OUT`
and answers with locators, types and lengths only (no `sql` in that mode, so no filter can confirm a guess);
`sqlite_snapshot` copies the database with its `-wal`, `-shm` and `-journal` (hashed), reads the
WAL against the format and has SQLite apply it in a copy, and `sqlite_query` takes that copy.

**Five recipes**, each saying what it prepares (`purpose` in its
`recipe.json`). `disk-volumes` (the partition table, and per filesystem a body
file, a path list and a MAC timeline) and `archive-members` (an archive's
member list) inventory: they read no file's contents. `ad1-items` inventories
an AccessData AD1 logical image (FTK Imager's custom content image, found by
its `ADSEGMENTEDFILE` header): every item with its size, times, the
digests the image records and a locator, each file inflated to check them,
every address, count and chain the image names held to what the image can hold
before it is followed, a metadata chain that items share written once, the data
no item leads to counted (a lost item makes the answer partial), nothing
extracted; `ad1_extract` writes the files out. `memory-windows` is a
broad extraction of a Windows memory image, Volatility's standard views of
the whole of it. `disk-timeline` is a broad extraction of a disk image,
Plaso's log2timeline over every partition and volume and a psort CSV timeline;
it takes hours on a large image, so it is not run by itself: the harness offers
it as a lead, and a seat runs it (`catalog_request recipe=computer-forensics-base/disk-timeline`)
or declines it with why. Each broad extraction lists its `exclusions` (for the
timeline: shadow copies, encrypted volumes without their key, unallocated
space, and the text inside documents).

## Host requirements

The Sleuth Kit and libewf are invoked as executables and are not redistributed
here: their licences and this project's do not combine in one work. BitLocker,
LUKS and virtual-disk tooling is declared optional, needed for one kind of case
rather than for the pack to work. `requires/host.json` has the whole list with
install commands; `scripts/pack.sh show computer-forensics-base` says which of
them this host has.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/swarm.sh start --pack computer-forensics-base ...
