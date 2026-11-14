---
id: artifacts/reconstruction
title: From a signature hit to a record you can cite
when: A carved hit must be readied for a parser, or its integrity judged.
needs: []
card: carve_handoff {"path": "<image>", "kind": "<kind as mem_carve names it>", "signature_offset": <offset>} readies one hit and calls no parser. Say whether you hold a signature hit, a slice or a validated record. Read validation and each check: unequal hive sequence numbers mean the hive changed while copied; a misplaced bin is fragmentation; "not checkable" is not intact. Slice bytes only with {"write_values": true} in a job with secret_output: true. No parser pack loaded: say the parse was not made. Does not show: that a plausible header is a whole structure.
tools: [mem_carve, carve_handoff]
mentions: [regkv, evtx_carve, mam_scan, prefetch_mam]
requires_host: []
---

Use when a `mem_carve` hit is to be handed to a parser, or a parse of a slice is to be cited. Not for finding the hits (`triage/carve-signatures`) or for working without a framework (`triage/no-framework`).

Four things look alike and are not: a **signature hit** (a few bytes at an offset), a **contiguous slice** cut from that offset, a **reconstructed virtual file** (the structure's pages joined in their virtual order, which this pack does not do) and a **validated record** (a parser's output for fields it checked). Name which one you hold.

**`carve_handoff`** takes one hit (`kind`, `signature_offset`) and readies the slice: the start by the Prefetch rule (four bytes before `SCCA`, only when those bytes are a known version), the cut by `mem_carve`'s own rule, `validation`, and checks a slice can fail:
- *Registry hive*: the base-block checksum, the two sequence numbers (unequal: the hive changed while it was copied and needs its transaction logs) and the chain of bins. A bin that is not where the chain puts it is `fragmentation`: the pages are not adjacent in the image.
- *Event log*: a file's chunks must each start with `ElfChnk` where the header puts them; a chunk has a header CRC-32.
- *SQLite pages*: the header's own fields only; the tool answers "not checkable" for adjacency, which is not "intact". A write-ahead log has no signature this pack carves, and is not joined to its database.

A slice is hashed only for a family that cannot be a credential store; a hive or a database is never hashed, and its bytes are written only with `write_values` in a job run with `secret_output: true`.

**Parsers, if the windows-forensics pack is loaded:** `regkv` for a hive, `evtx_carve` for event logs, `mam_scan` and `prefetch_mam` for Prefetch. `carve_handoff` names them and calls none; pass a result as `parser_result` to reference it. If the pack is not loaded, say the parse was not made.

**Shows.** Where a structure starts, how much of it the image holds, and whether the checks that exist broke.

**Does not show.** That a plausible header is a whole structure; that no break means the pages are adjacent; that a parse of a slice describes the original.

Record: the image's hash, the hit's kind and offsets, `validation`, each check's result, the cut's bounds and `cut_complete`, the job reference of a written slice (never its digest for a credential family).
Sensitive output: offsets and verdicts only; a slice is memory content, written only in a secret-output job and cited by job reference.
