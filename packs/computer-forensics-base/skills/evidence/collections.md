---
id: evidence/collections
title: Establish what a logical collection actually contains
when: Evidence arrives as copied files, an archive or an AD1 logical image.
needs: [evidence/imaging]
tools: [catalog_search, check_inputs, file_type, ad1_extract]
requires_host: [target-query, 7z]
mentions: [mft_records, evtx_query, regkv, CyLR, mac_apt.py]
---

More cases arrive as a collection than as an image, and the difference decides
half of what you can say. A collector copied a list of files off a machine, so
you hold the objects it collected, not a guaranteed view of a whole disk. Work
out its scope from the inventory, the collector's profile and its logs, and from
`file_type` over what is there. A collection may hold copied file system
metadata (an `$MFT`), databases with deleted records in them, slack collected as
an item (an AD1 can), memory captures, snapshots and nested disk images. Carving
can be possible inside the objects supplied even when the unallocated space of a
whole volume is not. The `-o <offset>` commands of this pack apply to an image
and not to the files of a collection, unless a disk image is among them.

The directory layout is a clue to the collector, not a statement of it. Confirm
the collector's name, version, configuration and logs before you use what it
implies:

    KAPE           a tree mirroring C:\, often with $MFT and $J at the root
    UAC            a .tar.gz with [bodyfile] [live_response] and per-artefact directories
    Velociraptor   a container zip, with an uploads/ tree and JSON result files
    CyLR           a zip mirroring the source paths, NTFS files pulled through the raw handle
    A hand-made copy   no manifest at all, and no way to know what was left out

**Work it as files.** Cite by path and hash instead of by inode, and verify the
collection with `check_inputs` like any input. A parser is chosen by the file's
type, not by where it was found: a hive is a hive, an `.evtx` is an `.evtx`, and
`$MFT` copied from a live volume parses as it would from an image. Use a parser the
run has: when the Windows pack is loaded, its `mft_records`, `evtx_query` and
`regkv` take a path; `mac_apt.py` for a macOS or UAC collection belongs to the
macOS pack and has image and architecture restrictions. `target-query` (dissect)
is optional here: check the job image's inventory before choosing either, since a
tool existing elsewhere in the repository does not make it available in this run.

The `archive-members` recipe lists a tar, zip or 7z without extracting it (it runs
`7z` for a 7z), and a member is read afterwards with the archive's own program as a
job: the base pack ships no member extractor yet.

A live collection is not one instant. Record the collection's interval and each
object's acquisition details, and keep companion files (database journals,
registry transaction logs) with the file they belong to.

**Does not show.** A collection shows the objects the collector copied, as it
copied them, and nothing of what it left. In the report state each excluded area
separately (whole-volume unallocated space, slack outside the
objects collected, files the target list did not name) and do not answer a
deleted-data question from the collection's label alone. "No whole-volume
carving was possible: the evidence is a KAPE collection, not an image" is a
bounded statement; "no deleted data exists" is not.

**Read the collector's own log.** It records the targets requested, collected,
skipped and failed, each with its reason. Keep that list. If the log or the
profile was not supplied, record that as a limitation. A target that failed does
not show locking, deletion or concealment: infer none without support.

**Do not trust the directory structure as a path.** Collectors rewrite paths to be
safe on the examiner's file system: a colon becomes something else, and a named
stream becomes a separate file with an invented name. Before you claim a file
lived at `C:\Users\x\y`, check the collector's manifest for the mapping.

**An AD1 image is a collection in a container.** FTK Imager's logical image
(`.ad1`, further segments `.ad2` and on) holds the files and folders the examiner
chose, with their times and the MD5 and SHA-1 the imager computed. The supplied
reader takes unencrypted version 4 images: an encrypted one (`ADCRYPT`), or another
version, needs a separately validated reader. The catalogue lists every item
(`members.tsv` of the `ad1-items` generation: `n`, its `locator`, the path under
the data source name, size, the image's own times with no zone recorded, the
recorded digests, the SHA-256 of the content and `check`). Find what you need with
`catalog_search which=members`, then write it out as a job:

    job_run tool=ad1_extract args={"image": "inputs/case.ad1", "members": ["ad1:item=<address>"]} inputs=["input:case.ad1"]

`members` takes the locator or `n`; a folder takes its subtree; none takes
everything. Use the locator when the listing was partial (a segment missing, an
item that could not be read): after a break the numbers are not a whole read's, the
locators are. Declare every segment in the job's `inputs`. The files land in the
store, cited as `job:<id>/<path>`, and the derived catalogue takes an archive or
a disk image inside in turn. Keep `image.json`, `attributes.tsv`, the generation's
coverage and the extraction manifest. A completed job is not proof the digests
matched: read each item's `check`, the call's `integrity_status` and every error.
`check` mismatch means the content is not what the imager hashed: say so before you
rely on the file. The extracted file's own times are the host's, not the item's;
use the recorded times, whose zone is unknown. The recipe and the extractor share
one reader, so their agreement is not independent corroboration. `target-query -f
walkfs inputs/case.ad1`, run as a job, is a second reader if the installed build
opens an AD1: check, and say so if it does not. Everything above about a logical
acquisition holds for an AD1.
