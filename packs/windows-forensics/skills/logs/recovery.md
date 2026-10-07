---
id: logs/recovery
title: Recovering records of a cleared or damaged log
when: A log is cleared, empty, damaged or incomplete and other acquired sources may hold its records.
needs: []
tools: [evtx_carve, evtx_query, sig_carve, icat_extract]
requires_host: []
---

Use when an event log is cleared or damaged and you look elsewhere for its records. Not for running the sweep and citing a carved record (`logs/carving`, only if you run `evtx_carve`) or for what silence shows (`logs/coverage`).

"The log was cleared" is where this starts. Clearing rewrites or replaces the file; chunks may survive in the file itself, in unallocated space, in a snapshot or in memory-related files, depending on allocation, overwrite, discard, fragmentation and what was acquired. Record each route and its result: "no records recovered" is bounded by the routes.

    the damaged .evtx      evtx_carve on the file: it finds chunks by their magic, whatever the file header says
    a whole old log        sig_carve with EVTX finds file headers; icat_extract takes a deleted file's inode
                           out of the image (`filesystem/deleted`)
    unallocated space      evtx_carve on the bytes, given as a raw file (`filesystem/carving`)
    pagefile.sys           evtx_carve; a hit is bytes in that file
    hiberfil.sys           evtx_carve reads stored bytes only; the file is compressed
    a memory image         evtx_carve; the offset is in the file, not a guest address
    a volume snapshot      an earlier copy of the whole file (`filesystem/shadowcopies`)

- `evtx_carve` searches contiguous bytes for chunk structures. It does not rebuild a chunk whose pages are scattered (a pagefile is paged in 4 KiB units) and the pack provides no hibernation decompressor: a sweep of one covers stored readable bytes only, unless the memory-forensics pack is loaded (look in the run's tool inventory) and a validated conversion exists.
- A hit in a pagefile or memory image identifies bytes in that source, not the process that held them or the file they belonged to. A snapshot is the log as of the snapshot, not of the clearing: compare it with the live file, do not substitute one for the other.
- **The clearing itself.** A 1102 (Security) or 104 (System) in the surviving log shows a clearing was recorded, with the account the audit named; the cleared channel is a field of the record. It can be missing from what you hold. A recorded clearing does not guarantee surviving chunks, and an empty channel with neither record does not show the clearing APIs were not used (`logs/coverage`).
- To read a whole recovered file use `evtx_query`. The pack does not convert carved records into an `.evtx` for a rule engine: read the carved XML directly (`logs/hunting`).

Sensitive output: `evtx_carve` and `evtx_query` return event XML that can hold a command line or a secret; run them as a job with `secret_output: true` (`logs/carving`).

Shows: records that survive in a named source, each with its own channel and computer. Does not show: that the log is whole, that the records belong to this machine, who cleared the log or why; a deletion, a clearing and a rollover can look alike, and only other sources tell them apart (`antiforensics/log-clearing`). Record: each route, source object and range, and the result.
