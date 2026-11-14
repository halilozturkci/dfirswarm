---
id: execution/prefetch
title: Prefetch
when: A .pf file: run count, last runs.
core: 2
needs: []
tools: [prefetch_mam, mam_scan, icat_extract]
requires_host: [sccainfo]
card: prefetch_mam {"path": "<NAME.EXE-HASH.pf>"}: read status and problems first; an unknown version or MAM method is unsupported, an unknown file_information_size gives run_count null. last_runs are the latest slots, not every run. Does not show: who ran it, or that it finished.
---

Use when you read a Prefetch file you have. Not for records carved from a raw source (`execution/prefetch-carved`, only if there is no file) or for what prefetch can support (`execution/overview`).

- **Name.** `<NAME>.EXE-<HASH>.pf` in `C:\Windows\Prefetch`: the file name and a hash of its path. One binary in two directories makes two files; the hash is not of the bytes. Extract with `icat_extract` (image, offset, digest); the `.pf`'s own file times are not run times.
- **Parser from the header, not an OS label.** `MAM` with method byte 4 is an Xpress Huffman body, `SCCA` at offset 4 a plain file; `prefetch_mam` reads either by the layout of the SCCA version (17, 23, 26, 30, 31; 31 is read with 30's layout, and the answer says so). Another version, or a MAM method other than 4, gives `status: unsupported` and no run count, time or string. A stream inflating past its declared size plus 64 KiB, or ending short, is a failed parse. Read `status` and `problems` before quoting a field.
- **Run count by layout.** In versions 26, 30 and 31 `file_information_size` (the word at 0x54 less 0x50) puts the run count: 224 at 0xD0, 216 at 0xC8. Any other size gives `run_count` null, no `last_runs`, a problem naming the size, and `status: partial`.
- **Fields.** `exe_name`, `prefetch_hash`, `run_count`; `last_runs` in UTC (one slot in 17 and 23, up to eight from 26) and the raw FILETIMEs in `last_runs_detail`; `filename_strings` from the section the header locates; `volumes_decoded`, the first volume entry only (device path, serial, creation time), with `volumes_claimed` counting the rest, undecoded. Metrics and trace chains are located, not decoded. Tie a string to a volume through the volume entries, not a drive letter.
- **Reading it.** The count and last runs are what the prefetcher recorded for this path; the slots are the latest runs, not all. The string list is files and directories it referenced, a bounded lead: a networking library in it shows no connection, and a reference to the Prefetch directory no deletion. Behaviour needs process records, `filesystem/journals`, logs or network evidence.
- **Second reader.** `sccainfo` (optional, other code) over the same file: compare count, last runs, volumes. `prefetch_mam` and `mam_scan` share one decoder (dissect.util's), so their agreement says nothing about it.
- A zero-length entry with named streams is an anomaly to enumerate (`filesystem/ads`), not a launch.

Shows: what the prefetcher recorded for one executable path. Does not show: who ran it, where it was started from, that it finished or had an effect, or that these are all its runs. Record: file digest, container and version, `status`, `file_information_size`, raw FILETIMEs.

Sensitive output: `prefetch_mam` withholds nothing; `filename_strings` are paths as stored. Describe a found secret by where it sits, its kind, length and what it grants, never its value, a fragment or a digest.
