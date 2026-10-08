---
id: memory/windows
title: Windows memory sources: what this pack's tools can say
when: A memory image, dump, hibernation file or pagefile needs a format, a route and its limits.
needs: []
tools: [file_type, mam_scan, evtx_carve, ioc_scan, sig_carve, yara_scan, utf16_urls, regkv]
requires_host: [strings, yara, vol, memprocfs]
mentions: [mem_profile, mem_fs]
---

Use when you hold a memory-related source (raw or wrapped image, crash dump, a VM's saved memory) and need its format and what this pack's byte-level tools can say. Not for process or network analysis, and not for a hibernation file or pagefile (`memory/hibernation-pagefile`, read it before you scan one).

Record where the source came from, its size, digest and format. `file_type` names a file from its first bytes; for a headerless raw image the format comes from the acquisition record, not the size. A scan's offset is an offset into this file, never a physical or process address.

These tools read bytes as stored; compressed or paged-out memory and structures split across pages are not reassembled.

- `strings -a -t d -e l IMAGE` lists UTF-16LE text with decimal offsets. `ioc_scan` searches your needles as ASCII and UTF-16LE, case matters; set `unique_only` false when each occurrence's offset matters. `utf16_urls`: `browser/strings`.
- `mam_scan` finds MAM-compressed Prefetch structures (`execution/prefetch-carved`), `evtx_carve` event chunks (`logs/carving`); a carved structure is bytes at an offset, not a file that existed or ran.
- `sig_carve` gives offsets and estimated sizes by signature; an estimate is not a boundary. A `regf` hit is at best a hive fragment: `regkv` reads one you wrote out, reports `problems` and a `status` of partial, and a key it cannot read is not an absent key.
- `yara_scan` (with `yara` and a rule file you name) answers rule, file, string identifier, offset, length and `finding_id`, never the matched bytes (`write_matches` writes them to a numbered file, in a job only). Read `scan_error_count`, `not_attempted` and `complete`. A match says the rule's condition held, not that the bytes are malicious or belong to a process.

`vol` and `memprocfs` are optional and not shipped (read the image's `tools.md`), and this pack carries no Windows kernel symbols. If the memory-forensics pack is loaded (look in the run's tool inventory), use its `triage/volatility` and `processes/injection`, its `mem_profile` and `mem_fs`, and its `strings/discipline` for how a string is recorded and attributed (a sound memory-only finding stands; no disk artefact is required first), in preference to these summaries. `memprocfs` needs FUSE, which a worker may not provide. A failed mount, missing symbol table or unsupported container is a limitation, and "no process list" is not "no processes".

Shows: that bytes were present at an offset of this source. Does not show: that a process held, loaded or sent them, that a carved structure was ever a file or was deleted, or that a search which found nothing covers other encodings, compressed or fragmented memory, or pages not captured. Record: source, digest, format basis, tool and parameters, offsets with their basis.

Sensitive output: memory holds secrets; run `strings`, `ioc_scan` context, `utf16_urls`, `evtx_carve` XML and any `vol` or `memprocfs` output as a job (`secret_output: true`).
