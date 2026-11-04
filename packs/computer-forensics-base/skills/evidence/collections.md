---
id: evidence/collections
title: Establish what a logical collection actually contains
when: Evidence arrives as copied files, an archive or an AD1 logical image.
needs: []
tools: [check_inputs, file_type]
requires_host: [target-query]
mentions: [mft_records, evtx_query, regkv, CyLR, KAPE, mac_apt.py]
---

Use when evidence arrives as copied files, an archive or an AD1. Not for a disk image (`evidence/imaging`).

A collection is not an image: that decides half of what you can say. A collector copied a list of files off a machine, so you hold the objects it collected, not a view of a whole disk. Find its scope in the inventory, the collector's profile and logs, and `file_type` over the files. A collection may hold copied file system metadata (an `$MFT`), databases with deleted records, slack taken as an item (an AD1 can), memory captures, snapshots and nested disk images, so carving can work inside the objects though a whole volume's unallocated space was not collected. This pack's `-o <offset>` commands apply to an image, not to a collection's files, unless a disk image is among them.

The directory layout is a clue to the collector, not a statement of it; confirm its name, version, configuration and logs first:

    KAPE           a tree mirroring C:\, often with $MFT and $J at the root
    UAC            a .tar.gz with [bodyfile] [live_response] and per-artefact directories
    Velociraptor   a container zip with an uploads/ tree and JSON results
    CyLR           a zip mirroring the source paths, NTFS files via the raw handle
    A hand-made copy   no manifest, and no way to know what was left out

**Work it as files.** Cite by path and hash, and verify it with `check_inputs`. Choose a parser by the file's type, not where it was found: a hive is a hive, and a copied `$MFT` parses as from an image. Use a parser the run has: with the Windows pack loaded, `mft_records`, `evtx_query` and `regkv` take a path; `mac_apt.py` belongs to the macOS pack (image and architecture restrictions); `target-query` is optional. Check the job image's inventory: a tool elsewhere in the repository is not in this run. Archives: `evidence/archives`; an AD1: `evidence/ad1`. A live collection is not one instant: record the interval and each object's acquisition details, and keep companion files (journals, registry transaction logs) with their file.

**Read the collector's own log:** the targets requested, collected, skipped and failed, each with its reason. Keep that list; a log or profile not supplied is a limitation. A failed target does not show locking, deletion or concealment: infer none without support.

**The directory structure is not a path.** Collectors rewrite paths to suit the examiner's file system: a colon becomes something else, a named stream a separate file with an invented name. Before you claim a file lived at `C:\Users\x\y`, check the collector's manifest for the mapping.

**Does not show.** A collection shows the objects the collector copied, as copied, and nothing of what it left. State each excluded area separately (whole-volume unallocated space, slack outside the objects, files the target list did not name); do not answer a deleted-data question from the collection's label alone. "No whole-volume carving was possible: the evidence is a KAPE collection, not an image" is a bounded statement; "no deleted data exists" is not.
