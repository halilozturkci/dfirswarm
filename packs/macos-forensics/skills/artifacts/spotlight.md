---
id: artifacts/spotlight
title: Spotlight index stores
when: A question may be answered by what the Spotlight index recorded about files, including removed ones.
needs: []
tools: []
requires_host: [mac_apt.py]
---

Use when a question might be answered from a Spotlight index store of the evidence. Not for the live index of a running Mac, or for the file system's own records (`filesystem/apfs`, `artifacts/fsevents`).

**Never `mdfind` the examiner's index.** `mdfind`, `mdls` and Spotlight search in a Finder window ask the examiner's Mac about its own index. They describe that Mac. Nothing they print is evidence about the subject. Work on a copy of the store.

**Where.** One store per volume, under `.Spotlight-V100/` at the volume's root (a volume group's Data volume and an external volume each have their own), in a subdirectory named for the store layout. Record the directory names, the store files and their sizes and times; do not assume which layout the build used. A user's metadata caches elsewhere are separate sources.

**Parsing is version-aware.** The store is Apple's own format and has changed between releases. A parser reads the layouts it was written for, and one that does not know the version reads nothing or reads wrongly: that is a parser limit, not an empty index. Whether the pinned `mac_apt.py` has a Spotlight plugin and reads this store's version is UNVERIFIED here (nothing in this pack ran it). Take plugin names from the installed copy's own help output, never from memory, and judge the run as `workflow/mac-apt` says.

**Reading entries.** An entry can be stale: the index lags the file system, keeps entries after a file moved or went, and is rebuilt (reindexed) after a repair or an upgrade, which drops or renews what it held. A path in the index shows that the path was indexed; a path absent shows nothing if the volume or the folder was excluded from indexing or the store was rebuilt. Times in an entry are the file's metadata as indexed, not the time of indexing or of any use, unless the field says so.

**Coverage.** State which volumes had a store, which were acquired, the layout, and the parser and version that read it. Keep apart "not indexed", "not acquired", "unsupported" and "read, no match".

Shows: that a path or attribute was indexed at some time, with the metadata as the index held it. Does not show: that a file exists now, that it was opened, or that an unlisted file never existed.
Record: the store directory, layout name, files and sizes, parser and version, plugin status, and the entry read.
Sensitive output: an index holds file names and paths and can hold text taken from user content. Read it as a job with `secret_output: true`; cite the entry and path, not content.
