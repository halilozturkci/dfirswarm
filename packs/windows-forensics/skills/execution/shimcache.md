---
id: execution/shimcache
title: ShimCache (AppCompatCache) and regkv
when: You need the compatibility cache's record of files, and the pack's only reader for it returns bytes.
needs: []
tools: [regkv]
requires_host: []
---

Use when you meet the AppCompatCache value in the SYSTEM hive. Not for Amcache (`execution/amcache`) or for deciding that a program ran (`execution/overview`).

- **Where.** `ControlSet00n\Control\Session Manager\AppCompatCache`, a binary value. Read the control set the question concerns (`registry/overview`), not a hard-coded `ControlSet001`.
- **What the pack gives.** `regkv` returns the value as hex with its registry type and length and decodes nothing: the pack has no ShimCache decoder. The layout varies with the Windows version, so decode it only with a parser validated for the build (an independent reader: `registry/readers`), and say the tool, its version and the format version.
- **Reading a decoded cache.** Record path, cached file metadata and order separately. A cached file time is the file's metadata, not an execution time, and the order is not a complete sequence of runs. How and when the cache reaches the registry, and what its flags mean, differ by implementation and build: a hive taken from a running system can lag the in-memory state, so an absence near the end of a timeline is not evidence.
- Sensitive output: `regkv` withholds secret-looking values by name or place (`registry/readers`); cache paths are not secrets.

Shows: the compatibility cache observed that path. Does not show: that the program ran, was started by whom, how often, or when (the time is the file's). Record: hive digest and state, control set, the raw value and the decoder with its version.
