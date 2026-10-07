---
id: filesystem/deleted
title: Deleted content and what was recovered
when: Files are missing, or you must say whether their content is recoverable from what was acquired.
needs: []
tools: [mft_records, icat_extract, sig_carve, file_carver]
requires_host: [fls, istat, tsk_recover]
---

Use when you ask whether deleted content exists and can be read back. Not for the Recycle Bin's metadata or for tools that wipe.

- "Deleted" is several states with different answers: say which one you hold and what was searched.
- A deleted entry whose record survives is unallocated on NTFS and keeps names, times and the run list until reuse. `mft_records` with `deleted_only` lists such records; `fls` with its deleted-entries option does the same where the Sleuth Kit reads the file system. Confirm allocation and sizes with `istat`, and record the logical, allocated and initialised size apart: `zero_initialised_size` explains an extraction of zeros, but not that no bytes survive in other extents, another stream, a snapshot, a backup or unallocated space, and it says nothing about who deleted the file.
- An extraction returns what the clusters hold now. If they were reused, it is another file's bytes under this name. Validate what `icat_extract` returned beyond its header: length against the record, the format's own structure (parse it with the tool that fits the type), the extents, any independent identifier such as a hash from another source, and a second parser where it matters (`filesystem/mft`). `tsk_recover` extracts every deleted file whose record the Sleuth Kit reads; its output is candidates, validated one by one, and it neither carves nor checks that the clusters are still the file's.
- Keep apart deletion, later reuse, overwrite, storage discard (SSD or virtual-disk TRIM and unmap) and gaps in the acquisition. To claim an overwrite, show it in the extents and the surviving content for the part you mean, allowing for sparse allocation, compression and encryption, which also give zeros or noise.
- Before you write "not recovered", name each route and its result: the record and extents (`istat`), the extraction and its validation, `tsk_recover`, a signature scan of unallocated space (`sig_carve`), a cut of a hit (`file_carver`: offset, size and hash, no name or times, so the image offset is its only provenance; `filesystem/carving`), the bin's $R, and the shadow copies and backups acquired (`filesystem/shadowcopies`). Record a secondary source that was not acquired or would not open.

Shows: content is, or is not, readable from these sources by these routes. Does not show: who deleted the file, why or whether on purpose, that it was copied elsewhere, that what came back is what the file held, or that it cannot be recovered from sources not supplied. Record: record number and sequence, the three sizes, each route with its result and validation.
Sensitive output: recovered content can hold secrets; extract in a job with `secret_output: true`.

Open `filesystem/recycle-bin` only if the file went through the Recycle Bin or a `$I` file is in play. For tools that wipe, `antiforensics/wiping`.
