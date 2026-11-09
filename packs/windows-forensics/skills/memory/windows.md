---
id: memory/windows
title: Windows memory
when: Image, dump, hiberfil: format, route, limits.
needs: []
tools: [file_type, mam_scan, evtx_carve, ioc_scan, sig_carve, yara_scan, utf16_urls, regkv]
requires_host: [strings, yara, vol, memprocfs]
mentions: [mem_profile, mem_fs]
---

Use when you hold a memory-related source (raw or wrapped image, crash dump, saved VM memory) and need its format and what this pack's byte-level tools can say. Not for process or network analysis, and not for a hibernation file or pagefile (`memory/hibernation-pagefile`, read it before you scan one).

Record where the source came from, its size, digest and format. `file_type` names a file from its first bytes; for a headerless raw image the format comes from the acquisition record, not the size. A scan's offset is an offset into this file, never a physical or process address.

These tools read bytes as stored; compressed or paged-out memory and structures split across pages are not reassembled.

- `strings -a -t d -e l IMAGE` lists UTF-16LE text with decimal offsets. `ioc_scan` searches your needles as ASCII and UTF-16LE, case matters; set `unique_only` false when each occurrence's offset matters. `utf16_urls`: `browser/strings`.
- `mam_scan` finds MAM-compressed Prefetch structures (`execution/prefetch-carved`), `evtx_carve` event chunks (`logs/carving`).
- `sig_carve` gives offsets and estimated sizes by signature, which are not boundaries. A `regf` hit is at best a hive fragment: `regkv` reads one you wrote out, reports `problems` and `status: partial`, and a key it cannot read is not an absent key.
- `yara_scan` (with `yara` and your rule file) answers rule, file, string identifier, offset, length and `finding_id`; the answer carries no matched bytes (`write_matches` writes them to a file, in a job only). Read `scan_error_count`, `not_attempted` and `complete`. A match says only that the rule's condition held.

`vol` and `memprocfs` are optional, not shipped (read the image's `tools.md`), and this pack carries no Windows kernel symbols: run `vol` with `--offline` and kernel-matching symbols; record its version line, the plugin, the image digest and the symbol identity. If the memory-forensics pack is loaded, use its `triage/volatility` and `processes/injection`, its `mem_profile` and `mem_fs`, and its `strings/discipline` for how a string is recorded and attributed over these summaries. A failed mount, missing symbol table or unsupported container is a limitation, and "no process list" is not "no processes".

Shows: that bytes were present at an offset of this source. Does not show: that a process held, loaded or sent them, that a carved structure was ever a file or was deleted, or that a search which found nothing covers other encodings, compressed or fragmented memory, or pages not captured. Record: source, digest, format basis, tool and parameters, offsets with their basis.

Sensitive output: memory holds secrets; run `strings`, `ioc_scan` context, `utf16_urls`, `evtx_carve` XML and any `vol` or `memprocfs` output as a job (`secret_output: true`). `utf16_urls` masks by parameter name and user-info, so a token in a path is printed; `yara_scan` keeps matched bytes out of the answer, but its rule and string identifiers are printed. Describe a found secret by where it sits, its kind, length and what it grants, never its value, a fragment or a digest.
