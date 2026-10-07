---
id: execution/amcache
title: Amcache inventory and amcache_apps
when: You need to identify a file by path or hash from Amcache.hve, or say what an Amcache entry means.
needs: []
tools: [amcache_apps]
requires_host: []
---

Use when you read Amcache.hve. Not for ShimCache (`execution/shimcache`) or for deciding that a program ran (`execution/overview`).

- **An entry means the inventory recorded this file**, not that the program ran; a missing entry does not mean it did not. Which entries exist, and when they were written, depends on the build, the inventory task and the hive's state.
- **Source.** `Windows/AppCompat/Programs/Amcache.hve` is a registry hive: work on a copy with its `.LOG1` and `.LOG2` beside it. `hive_dirty` and the logs `amcache_apps` names are read as in `registry/overview`; say which state you read. For a second reader, `registry/readers`.
- **Layouts.** `amcache_apps` reads both when both are present and names the layout in each row: `File` (the older one, numbered values, named by a published research mapping that is not Microsoft documentation: say so when a field name matters) and `InventoryApplicationFile` (the newer layout, named values). Read `layouts_found` and `rows_by_layout` first; "neither layout is present" is an answer about this hive, not the machine. `status: partial` (`rows_failed`, `problems`) is not the whole inventory.
- **Row fields.** Path, publisher and version values the layout holds; the hash as stored (`sha1_raw`) with the 40-digit form beside it (`sha1`; `file_id_sha1` for the newer layout's `FileId`), stripped only where the stored value is four zeros and 40 hex digits; `key_last_modified` (UTC to seven fractional digits, raw FILETIME beside it) and, in the older layout, the numbered FILETIME values. `linker_compile_time_utc` is the PE header's 32-bit Unix-epoch value, converted as one with the raw value kept: metadata set when the binary was linked, chosen by whoever built it, not a run time and not a trustworthy build date.
- **The hash** lets you test a file whose bytes are gone against a hash you hold. What range of the file the inventory hashed is not established here and may depend on the build: a mismatch with a whole-file hash is not a different file until that is settled, and a match is a match of that range. Other sources, process-creation telemetry among them, may carry hashes too.
- A negative names the hive, its sequence state and the layouts read; a user or volume whose hive was not collected is not a file with no entry.

Shows: the inventory held an entry for that path and file. Does not show: that the program ran, who ran it or from which account, how often, that it finished, that the file was present at any date the entry does not carry, or (for a missing entry) that the file never existed there. Record: hive copy digest and state, layout per row, `sha1_raw` and `sha1`, raw FILETIMEs.
