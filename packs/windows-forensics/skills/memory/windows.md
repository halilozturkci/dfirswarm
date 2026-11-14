---
id: memory/windows
title: Windows memory
when: Image, dump, hiberfil: format, route, limits.
needs: []
tools: [file_type, mam_scan, evtx_carve, ioc_scan, sig_carve, yara_scan, utf16_urls, regkv]
requires_host: [strings, yara, vol, memprocfs]
mentions: [mem_profile, mem_fs]
card: yara_scan {"rules": "<rules.yar>", "target": "<image>"}: a match says only that the rule held at an offset of this file, not a process address; matched bytes stay out. Read scan_error_count and not_attempted before a negative. Does not show: that a process held or loaded the bytes.
---

Use when you hold a memory source (raw or wrapped image, crash dump, saved VM memory) and need its format and what byte-level tools can say. Not for process or network analysis, and not for a hibernation file or pagefile (`memory/hibernation-pagefile`, read it before you scan one).

Record where the source came from, its size, digest and format. `file_type` names a file from its first bytes; for a headerless raw image the format comes from the acquisition record, not the size. A scan's offset is an offset into this file, never a physical or process address.

These tools read bytes as stored; compressed or paged-out memory and structures split across pages are not reassembled.

- `strings -a -t d -e l IMAGE` lists UTF-16LE text with decimal offsets. `ioc_scan` searches your needles as ASCII and UTF-16LE, case matters; `unique_only` false gives each occurrence's offset. `utf16_urls`: `browser/strings`.
- `mam_scan` finds MAM-compressed Prefetch structures (`execution/prefetch-carved`), `evtx_carve` event chunks (`logs/carving`).
- `sig_carve` gives offsets and estimated sizes by signature, which are not boundaries. A `regf` hit is at best a hive fragment: `regkv` reads one you wrote out, reports `problems` and `status: partial`, and a key it cannot read is not an absent key.
- `yara_scan` (with `yara`) answers rule, file, string identifier, offset, length and `finding_id`, no matched bytes (`write_matches` writes them, in a job). Read `scan_error_count`, `not_attempted` and `complete`.

`vol` and `memprocfs` are optional and not shipped (the image's `tools.md`); this pack carries no Windows kernel symbols: run `vol --offline` with matching symbols and record its version, plugin, image digest and symbol identity. With the memory-forensics pack loaded, its `triage/volatility`, `processes/injection`, `mem_profile`, `mem_fs` and `strings/discipline` come first. A failed mount, missing symbol table or unsupported container is a limitation, and "no process list" is not "no processes".

Shows: that bytes were present at an offset of this source. Does not show: that a process held, loaded or sent them, that a carved structure was ever a file or was deleted, or that a search which found nothing covers other encodings, compressed memory or pages not captured. Record: source, digest, format basis, tool and parameters, offsets with their basis.

Sensitive output: memory holds secrets; run `strings`, `ioc_scan` context, `utf16_urls`, `evtx_carve` XML and any `vol` or `memprocfs` output as a job (`secret_output: true`). `utf16_urls` masks by parameter name and user-info, so a token in a path is printed; `yara_scan` prints rule and string identifiers, not matched bytes. Describe a found secret by where it sits, its kind, length and what it grants, never its value, a fragment or a digest.
