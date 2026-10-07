---
id: filesystem/shadowcopies-open
title: Reading files from a shadow copy
when: A store is listed and you must read an earlier hive, log or file from it.
needs: [filesystem/shadowcopies]
tools: [vss_stores, extract_stream, mft_records, regkv, evtx_query]
requires_host: [vshadowmount, fls]
---

Use when a store listed by `vss_stores` has to be read. Not for deciding whether stores exist (`filesystem/shadowcopies`).

- Mount in your own VM, not in a job. A job is one tool call with a read-only run, and a FUSE mount lives in the agent's VM and is that VM's alone: run the `mount_argv` commands exactly as returned, from your seat (the mount directory defaults to `work/<your id>/vss`; stores appear as `vss1`, `vss2`, ...). `vshadowmount` needs FUSE, which a worker may not provide; if it is missing, say the mount route was unavailable and which routes remain.
- Use the ordinary toolkit on each `vssN` as if it were a volume: `fls -r`, and `extract_stream` with the `vssN` file as the image, offset 0 and an `output` under `work/<your id>/...`.
- A job cannot see your mount. Copy the derived hive or log under `work/<your id>/`, seal it with `job_run import=`, then read it with `regkv` or `evtx_query` in a job.
- For every artefact taken from a snapshot record the source volume, store identifier, snapshot creation time, extraction path and the artefact's own times, and cite both the snapshot time and the artefact's.
- A hive or event log in a snapshot is the state at snapshot time. A difference from the live copy shows two observed states: it excludes neither intermediate changes nor a restoration to an earlier value, and dates a change no more closely than the two observations. A log can be caught mid-write, and events after the snapshot are not in it. For a cleared log try the snapshot before carving (`logs/recovery`).
- A file taken before a deletion, wipe or encryption shows what the volume held then; whether application state was consistent at that moment is usually unknown.
- To compare `$MFT` states extract entry 0 from each snapshot and run `mft_records` on each; match records by entry and sequence, since a number can be another file after reuse.
- A snapshot is rebuilt from the volume plus the old blocks it kept. A file unchanged since is read from the same clusters: the same bytes, not a surviving second copy. An unavailable or incomplete store cannot support a claim that something was absent.

Shows: what the volume held at the snapshot's creation. Does not show: what happened between two states, who changed or deleted anything, or the first or only change. Record: store identifier and creation time, how it was exposed (or that the mount was unavailable), extraction path, sealed import, the artefact's own times.
Sensitive output: hives, logs and files from a snapshot can hold secrets, and `regkv` withholds by name or place only; read them in a job with `secret_output: true` where they may.
