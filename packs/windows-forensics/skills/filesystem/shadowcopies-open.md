---
id: filesystem/shadowcopies-open
title: Reading a shadow copy
when: An earlier hive, log or file.
needs: [filesystem/shadowcopies]
tools: [vss_stores, vss_materialise, extract_stream, mft_records, regkv, evtx_query]
requires_host: [vshadowmount, fls, icat]
---

Use when a store listed by `vss_stores` has to be read. Not for deciding whether stores exist (`filesystem/shadowcopies`).

- `vss_materialise` does the reading: give it the image, the offset in bytes, the store numbers `vss_stores` listed and the paths wanted (`/Windows/System32/config/SYSTEM`). It mounts the selected stores with `vshadowmount` under its own directory (FUSE), copies each path out of each store with `fls` and `icat`, unmounts, and answers which store has which path, the copies with sha256 and the store's identifier and creation time, and whether each copy is the same as the live file. A path absent from a store is a fact about that snapshot. Without FUSE it answers `blocked: no FUSE` and writes nothing: say the route was unavailable.
- SAM, SECURITY and NTDS.dit are copied only with `copy_credentials` in a `secret_output` job, and no digest of them is made. Read a copied hive or log with `regkv` or `evtx_query` in a job.
- By hand, only where the tool is unavailable: run the `mount_argv` commands `vss_stores` returned from your seat (a mount lives in the agent's VM and is that VM's alone), then `fls -r` and `extract_stream` on each `vssN` with offset 0.
- For every artefact taken from a snapshot record the source volume, store identifier, snapshot creation time, extraction path and the artefact's own times, and cite both the snapshot time and the artefact's.
- A hive or event log in a snapshot is the state at snapshot time. A difference from the live copy shows two observed states: it excludes neither intermediate changes nor a restoration to an earlier value, and dates a change no more closely than the two observations. A log can be caught mid-write, and events after the snapshot are not in it. For a cleared log try the snapshot before carving (`logs/recovery`).
- A file taken before a deletion, wipe or encryption shows what the volume held then; whether application state was consistent at that moment is usually unknown.
- To compare `$MFT` states extract entry 0 from each snapshot and run `mft_records` on each; match records by entry and sequence, since a number can be another file after reuse.
- A snapshot is rebuilt from the volume plus the old blocks it kept. A file unchanged since is read from the same clusters: the same bytes, not a surviving second copy. An unavailable or incomplete store cannot support a claim that something was absent.

Shows: what the volume held at the snapshot's creation. Does not show: what happened between two states, who changed or deleted anything, or the first or only change. Record: store identifier and creation time, how it was exposed (or that the mount was unavailable), extraction path, sealed import, the artefact's own times.
Sensitive output: hives, logs and files from a snapshot can hold secrets, and `regkv` withholds by name or place only; read them in a job with `secret_output: true` where they may. Describe a found secret by where it sits, its kind, length and what it grants, never its value, a fragment or a digest.
