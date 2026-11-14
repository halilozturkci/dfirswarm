---
id: filesystem/shadowcopies
title: Shadow copies
when: Which snapshots an image holds.
needs: []
tools: [vss_stores, vss_materialise]
requires_host: [vshadowinfo, vshadowmount, mmls]
card: vss_stores {"image": "<raw image>", "offset": <bytes>}: mmls gives sectors, so multiply by the sector size it prints; a wrong unit is failed, never "no stores". Zero stores is not that none was made or one deleted. Does not show: what a store contains.
---

Use when you ask which volume shadow copies exist. Not for reading files out of one (pointer at the end).

- A snapshot is a second observed state of the volume, from its own `System Volume Information`: look there for an earlier hive, log or file before you call one gone. A logical or targeted collection does not hold it.
- `vss_stores` takes a raw volume or disk image and the volume offset in bytes, runs `vshadowinfo`, and lists each store's identifier, creation time and volume size, with the `mount_argv` that would expose it. It mounts nothing, and a listed store is not an examined one. An E01 must be exposed raw first (`evidence/imaging`); an EWF signature is a problem.
- To copy files out of chosen stores, use `vss_materialise` (`filesystem/shadowcopies-open`).
- The offset unit changes here: `mmls` and the Sleuth Kit use sectors, `vshadowinfo` and `vshadowmount` bytes. Multiply the start sector by the logical sector size `mmls` prints, not an assumed 512, and record both numbers. A wrong unit gives "unable to open volume" on a sound image; the tool answers `failed`, never "no stores".
- Read `status`, `exit_code`, `store_count`, `stores_claimed` and `problems` before the list; the whole `vshadowinfo` output is in `stdout_file` and `stderr_file`, and a rerun keeps its own pair (`earlier_output_files`).
- `failed` (exit 1): no usable answer (bad offset or unit, non-raw image, timeout, unrecognised output) and no statement about shadow copies; fix the cause.
- `partial`: a problem was recorded (the stores read differ from the number claimed, say); do not count stores from that list.
- `complete` with zero stores: "`vshadowinfo`, at this offset, reported 0 stores". It does not show that none was made or that one was deleted: never created, deleted, aged out of a size limit and not part of the acquired data all give it. A command that removes shadow copies, a System 7036 and low free space are context; attribute a deletion only where evidence establishes it and its outcome (`logs/security`, `logs/powershell`). Otherwise: "no stores were found at this offset and the reason is not established".
- `interrupted` (a stop by signal) is no answer either. `complete` with stores: list each identifier and creation time.

Shows: what `vshadowinfo` found in this volume's metadata at this offset. Does not show: that none ever existed, that any was deleted, or what a store contains. Record: image, offset in bytes and the sector arithmetic, `status`, both store counts, `problems`, the output files.

Sensitive output: `vss_stores` writes its output files at 0600; a store is as sensitive as the volume. Describe a found secret by where it sits, its kind, length and what it grants, never its value, a fragment or a digest.

Open `filesystem/shadowcopies-open` only if you must read files, hives or logs out of a store.
