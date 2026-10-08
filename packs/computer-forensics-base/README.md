# Computer Forensics Base Pack

The method and the tooling every examination needs, whatever the operating
system the evidence came from: work out what you were handed and where the
volume starts, verify the evidence, build a catalogue before spending a token,
extract and carve, tell an encrypted volume from an unreadable one, keep a
timeline that survives a second reader, and write a report whose every claim
cites something checkable.

Platform-specific artefact knowledge lives in the packs that depend on this one.

## What it carries

**Eleven skills**, fetched one at a time by the agents that need them:

| | |
| --- | --- |
| `evidence/verify` | establish the evidence's identity, integrity and provenance, and what a hash match does and does not show |
| `evidence/imaging` | the container, the storage layers, the address space and the offset every command needs |
| `evidence/catalog` | read the catalogue with its coverage and revision before you spend a token |
| `evidence/collections` | the evidence is a zip, a directory tree or an AD1, not a disk: what it contains and what it cannot show |
| `filesystem/extract` | get a file out of an image, and say which record it came from |
| `filesystem/carving` | recover candidate structures where there is no file system, and say how far to trust them |
| `filesystem/encrypted` | a volume the toolkit cannot read: encryption is one explanation among several |
| `timeline/build` | a timeline a second reader can trust: the raw value, the zone's history and clock uncertainty kept |
| `timeline/super` | the window an incident happened in, from evidence too large to read |
| `reporting/citations` | every claim resolves to an inspectable observation, and a negative is bounded |
| `reporting/disagreement` | disputing, correcting and republishing, through the ledger's own acts |

**Fourteen tools**: `image_layout`, `check_inputs`, `catalog_search`,
`icat_extract`, `sig_carve`, `file_carver`, `ioc_scan`, `chunk_needles`,
`file_type`, `sqlite_query`, `feature_scan`, `timeline_super`,
`timestamp_decode`, `ad1_extract`. `file_type` to `timestamp_decode` arrived
with the packs that depend on this one: a tool every pack would have carried
belongs here once, not in each of them. `ad1_extract` writes an AccessData
AD1 logical image's files out, checked against the digests the image
records; run as a job, what it writes is catalogued in turn.
Every one takes JSON on stdin and returns JSON, and every call lands on the
run's trace under the calling agent's name. What they return is bounded and
says so: a carve is a candidate with `boundary: validated` or `heuristic`, a
scan returns locators and not the bytes around a hit (those go to a sealed
file only when a job asks, with `secret_output`), a run that ended part way is
`partial` with the exit codes of its stages, and a count never depends on how
the file was read. A tool with a time budget of its own keeps that budget
inside the manifest's limit, so reaching it is reported (`partial`, `not_checked`,
`interrupted`) and is not a kill with nothing said. `sqlite_query` reads the main
database file and reports a write-ahead log beside it without applying it.

**Five recipes**, each saying what it prepares (`purpose` in its
`recipe.json`). `disk-volumes` (the partition table, and per filesystem a body
file, a path list and a MAC timeline) and `archive-members` (an archive's
member list) inventory: they read no file's contents. `ad1-items` inventories
an AccessData AD1 logical image (FTK Imager's custom content image, found by
its `ADSEGMENTEDFILE` header): every item with its size, times, the
digests the image records and a locator, each file inflated to check them,
every claim the image makes bounded before it is followed, nothing
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
