---
id: filesystem/indx
title: Index slack and names a directory no longer lists
when: You need file names a directory index still holds after the file left it.
needs: [filesystem/mft]
tools: [indx_carve, extract_stream, usn_journal]
requires_host: [istat]
---

Use when you recover names from a directory's $I30 index. Not for the file's own record (`filesystem/mft`) or deletion as such (`filesystem/deleted`).

- Take the directory's `$INDEX_ALLOCATION` (type 160, the `$I30` index; `istat` on the directory lists its attributes), extract it with `extract_stream` by its `<entry>-<type>-<id>` address under your own `work/<your id>/...`, hash it, and give it to `indx_carve`. A raw blob can be swept for INDX blocks with no directory attached. The small index inside a record's `$INDEX_ROOT` is not read.
- `source` is `live` (the directory lists it) or `slack` (stale). A slack entry gives name, parent and four cached times with `block_offset` and the byte `offset`, and no record number: tie it to a record by name, parent and times, and say so.
- Integrity travels with the entry: `fixup_ok`, `node_ok`, `salvaged`. Entries of a salvaged block are left out unless `include_unreliable` is true; the answer counts `blocks_salvaged` and `entries_excluded_unreliable` (partial). Report the count with the finding and mark any salvaged entry you show.
- A live entry that cannot be read as a name is a problem with its MFT reference, counted in `live_entries_unreadable` (partial). A live entry with odd values (a parent that is not a believable directory, created and modified both 0 or all ones) is returned with `unreliable_reasons` and counted in `live_entries_flagged_unreliable`.
- The cached times are historical metadata of that structure: not the file's current times, and no proof they were unaltered. A parsed name is structurally plausible, not verified. A slack entry does not say the file was deleted or wiped: a rename, a move out of the directory or an index rebalance leaves the same trace. Corroborate with the $MFT record where one survives and with `usn_journal`.

Shows: this directory index once held this name, parent and these times. Does not show: deletion, wiping, who acted, or the file's current state. Record: block offset, entry offset, `source`, the three integrity flags, the excluded counts, and the corroboration tried.
