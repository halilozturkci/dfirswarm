---
id: evidence/ad1
title: An AD1 image is a collection in a container
when: Evidence is an FTK Imager logical image (.ad1).
core: 1
card: ad1_extract: image is the first segment (the job gets the rest of the set). List first ({"list": true}: no file written; rows n, locator, type, size, path), then name what you need: members, a list of locators ("ad1:item=<address>", the locator column) OR item numbers as numbers (1234, the n column), never ad1:item=<n>; or paths (["*/Users/*/NTUSER.DAT"]); or members_file. The whole tree only with whole: true.
tools: [ad1_extract, catalog_search]
requires_host: [target-query]
---

Use when evidence is an FTK Imager logical image (`.ad1`, with `.ad2` and later segments). Not for a disk image or a plain archive (`evidence/archives`).

An AD1 holds the files and folders the examiner chose, their times and the
MD5 and SHA-1 the imager computed. The reader takes unencrypted version 4 images;
`ADCRYPT` or another version needs a separately validated reader. List first,
then take what you need:

    job_run tool=ad1_extract args={"image": "inputs/case.ad1", "list": true} inputs=["input:case.ad1"]
    job_run tool=ad1_extract args={"image": "inputs/case.ad1", "members": ["ad1:item=<address>"]} inputs=["input:case.ad1"]
    job_run tool=ad1_extract args={"image": "inputs/case.ad1", "members": [<n>]} inputs=["input:case.ad1"]

`list` writes no file out: every item's `n`, `locator`, type, size and path, in
`ad1_list.tsv`. The catalogue's `members.tsv` (`catalog_search
which=members`) adds times, digests and `check`, which says `pending` until its
digest pass ends.
`members` takes a locator (the text `ad1:item=<address>`, the `locator` column) OR
the item's number `n` (a number, the `n` column); never `ad1:item=<n>`. `paths`
takes patterns over the whole path (`["*/Users/*/NTUSER.DAT"]`), `members_file` a
list or a cut of one. A folder takes its subtree. Naming nothing writes a small
image out and answers for a large one with the list: `whole: true` writes the
whole tree, hours and the image's size again: on purpose. After a break in
a partial listing the numbers are not a whole read's, the locators are. Name the first segment
only, in `image` and in `inputs`: the job is given the image's whole
segment set from it. Files are cited as `job:<id>/<path>`; the derived catalogue
takes an archive or disk image inside.

A `members` call for files stops once they are written: `selection` answers for
them, and `image_status: not_checked` says the image-wide checks did not run. A
folder, whole or `paths` call walks to the end, where data the tree does not lead to (a lost
pointer) makes it `partial`. A completed job is not
proof the digests matched: read each `check`, `integrity_status` and every error.
`check` mismatch: the content is not what the imager hashed; say so before
relying on it. Extracted files carry the host's times; use the recorded,
whose zone is unknown. Recipe and extractor share one reader: their agreement is
not corroboration. `target-query -f walkfs inputs/case.ad1`, as a job, is a second
reader if the installed build opens an AD1: check; say so if not. What
`evidence/collections` says of a logical acquisition holds for an AD1.

**Does not show.** That the source held nothing but what the imager was told to take, that the recorded digests were right when made, or the zone of the recorded times.
