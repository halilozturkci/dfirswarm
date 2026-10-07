---
id: execution/prefetch-carved
title: Prefetch records carved from a raw source
when: No .pf file, but a memory image, pagefile or disk region may hold Prefetch records.
needs: [execution/prefetch]
tools: [mam_scan]
requires_host: []
---

Use when you sweep a raw source for `MAM\x04` Prefetch records. Not for a .pf you have (`execution/prefetch`) or for naming the file a record came from (nothing here can).

- `mam_scan` finds `MAM\x04` followed by a declared size between `min_uncomp` and `max_uncomp` (defaults 1024 and 2,000,000); a size outside is counted in `size_out_of_range` and not read. Each candidate is inflated to its declared size and read by the layout of its version, as in `execution/prefetch`, and carries its offset, `attempted_range` and `file_information_size`.
- **Read the accounting before any conclusion:** `candidates`, `parsed`, `failed` with `failed_by_reason` (the first failures in `failures`), `filtered_by_name` (a failure is counted before `name_filter` applies), `unsupported_variant_signatures` (`MAM\x84` signatures, counted and not read), `scanned_from`, `scanned_to`, and `status`, which is `partial` when any candidate failed. A source that cannot be read part way is a failure that says how far the scan got.
- **A hit** is a Prefetch structure at an offset of the source you scanned. It carries no file name, owner or path; an unsupported version is a hit with `supported: false` and no version-dependent field. A candidate that does not inflate to a Prefetch structure stays a failure with its offset.
- **Coverage.** The tool does not search for plain `SCCA` records and does not reassemble fragments, so a negative is bounded to `MAM\x04` records in the range scanned. An offset is an offset into this file, not a physical or virtual address.
- **A missing .pf** is not a negative by itself: establish the prefetcher's configuration in the SYSTEM hive (`registry/overview`), its service state and what was collected.

Shows: a Prefetch structure was in the source at that offset. Does not show: that a file of that name existed on disk, was deleted or ran in this session. Record: source digest and range scanned, the accounting fields, each hit's offset, version and `file_information_size`.
