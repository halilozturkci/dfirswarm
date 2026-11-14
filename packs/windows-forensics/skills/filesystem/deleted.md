---
id: filesystem/deleted
title: Deleted content
when: Missing files: recoverable here?
needs: []
tools: [mft_records, icat_extract, sig_carve, file_carver, thumbcache_read]
requires_host: [fls, istat, tsk_recover]
card: thumbcache_read {"path": "<Explorer directory>"}: a thumbnail is a rendering the cache kept, not the file, and does not say when or by whom it was opened. Before "not recovered", name each route and its result. Does not show: who deleted the file, or that it cannot be recovered elsewhere.
---

Use when you ask whether deleted content exists and can be read back. Not for the Recycle Bin's metadata or for tools that wipe.

- "Deleted" is several states with different answers: say which one you hold and what was searched.
- A deleted entry whose record survives is unallocated on NTFS and keeps names, times and the run list until reuse. `mft_records` with `deleted_only` lists such records; `fls` with its deleted-entries option does the same. Confirm allocation and sizes with `istat`, and record the logical, allocated and initialised size apart: `zero_initialised_size` explains an extraction of zeros, not that no bytes survive in other extents, streams, snapshots, backups or unallocated space.
- An extraction returns what the clusters hold now. If they were reused, it is another file's bytes under this name. Validate what `icat_extract` returned beyond its header: length against the record, the format's structure, the extents, an independent identifier such as a hash from another source, and a second parser where it matters (`filesystem/mft`). `tsk_recover` extracts every deleted file whose record the Sleuth Kit reads; its output is candidates, validated one by one; it neither carves nor checks that the clusters are still the file's.
- Keep apart deletion, later reuse, overwrite, storage discard (TRIM, unmap) and gaps in the acquisition. To claim an overwrite, show it in the extents and surviving content for that part, allowing for sparse allocation, compression and encryption (zeros or noise too).
- Before you write "not recovered", name each route and its result: the record and extents (`istat`), the extraction and its validation, `tsk_recover`, a signature scan of unallocated space (`sig_carve`), a cut of a hit (`file_carver`: no name or times, the image offset is its provenance; `filesystem/carving`), the bin's $R, and the shadow copies and backups acquired (`filesystem/shadowcopies`). Record a secondary source that was not acquired or would not open.
- On a host whose files were encrypted or wiped, the thumbnail and icon caches may hold renderings made before: `thumbcache_read`.

Shows: content is, or is not, readable from these sources by these routes. Does not show: who deleted the file, why or whether on purpose, that it was copied elsewhere, that what came back is what the file held, or that it cannot be recovered from sources not supplied. Record: record number and sequence, the three sizes, each route with its result and validation.
Sensitive output: recovered content can hold secrets; extract in a job with `secret_output: true`. Describe a found secret by where it sits, its kind, length and what it grants, never its value, a fragment or a digest.

Open `filesystem/recycle-bin` only if the file went through the Recycle Bin or a `$I` file is in play. For tools that wipe, `antiforensics/wiping`.
