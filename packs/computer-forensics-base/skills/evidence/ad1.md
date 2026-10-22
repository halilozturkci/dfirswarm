---
id: evidence/ad1
title: An AD1 image is a collection in a container
when: Evidence is an FTK Imager logical image (.ad1).
tools: [ad1_extract, catalog_search]
requires_host: [target-query]
---

Use when evidence is an FTK Imager logical image (`.ad1`, with `.ad2` and later segments). Not for a disk image or a plain archive (`evidence/archives`).

FTK Imager's logical image
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
coverage and the extraction manifest. Data the tree does not lead to (a lost pointer; the format has no item count) makes the answer `partial`. A completed job is not proof the digests
matched: read each item's `check`, the call's `integrity_status` and every error.
`check` mismatch means the content is not what the imager hashed: say so before you
rely on the file. The extracted file's own times are the host's, not the item's;
use the recorded times, whose zone is unknown. The recipe and the extractor share
one reader, so their agreement is not independent corroboration. `target-query -f
walkfs inputs/case.ad1`, run as a job, is a second reader if the installed build
opens an AD1: check, and say so if it does not. Everything `evidence/collections` says about a
logical acquisition holds for an AD1.

**Does not show.** An AD1 shows the files the imager was told to take and the digests it recorded. It does not show that the source held nothing else, that the digests were right when made, or the zone of the recorded times.
