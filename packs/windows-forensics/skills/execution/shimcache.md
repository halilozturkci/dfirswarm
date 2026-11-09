---
id: execution/shimcache
title: ShimCache, AppCompatCache
when: Records of files seen.
needs: []
tools: [userassist_bam_shimcache, regkv]
requires_host: []
---

Use when you meet the AppCompatCache value in the SYSTEM hive. Not for Amcache (`execution/amcache`) or for deciding that a program ran (`execution/overview`).

- **Where.** `ControlSet00n\Control\Session Manager\AppCompatCache`, a binary value. Read the control set the question concerns (`registry/overview`), not a hard-coded `ControlSet001`.
- **What the pack gives.** `userassist_bam_shimcache` decodes the value into one record per entry (`path`, `last_modified`, flags, `data_length`, `entry_position`) with `layout` and `layout_basis` (the layouts it knows are in its manifest). A header or an entry that fits none of them is `unsupported`, bytes kept. Its offsets are from published notes and are not verified against real hives; an entry's data blob is counted, not decoded. Nothing cross-checks it (`cross_check` is `not_run`; an independent reader: `registry/readers`). Say the tool, its `parser` and the `layout`. `regkv` returns the value as hex only.
- **Reading a decoded cache.** Record path, cached file metadata and order separately. A cached file time is the file's metadata, not an execution time, and the order is not a complete sequence of runs. How and when the cache reaches the registry, and what its flags mean, differ by implementation and build: a hive taken from a running system can lag the in-memory state, so an absence near the end of a timeline is not evidence.
- Sensitive output: `regkv` withholds secret-looking values by name or place (`registry/readers`); cache paths are not secrets. Describe a found secret by where it sits, its kind, length and what it grants, never its value, a fragment or a digest.

Shows: the compatibility cache observed that path. Does not show: that the program ran, was started by whom, how often, or when (the time is the file's). Record: hive digest and state, control set, the raw value and the decoder with its version.
