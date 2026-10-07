---
id: apps/fragments
title: Reading a sqlite_freespace answer
when: Use only if you ran sqlite_freespace and must report what its fragments are. Not for choosing whether to run it.
needs: [apps/databases]
tools: [sqlite_freespace]
requires_host: []
---

Use only if you ran `sqlite_freespace` and must report what its fragments are. Not for deciding whether to run it (`apps/databases`).

**The text is withheld.** The answer gives, per fragment: `finding_id`, page, `where` (freelist trunk or leaf page, unallocated space in page, freeblock in page), byte `offset`, `bytes`, `characters`, `encoding`. The text itself is written only on `write_values: true`, in a job run with `secret_output: true`, to `$OUT/sqlite-freespace-values.jsonl` (mode 0600); outside a job the request is refused. Read that file in the job; do not paste values into a post or the ledger.

**Offsets** are file byte positions, read back and compared (`offset_verified`). A freeblock fragment starts after the freeblock's 4-byte header and carries `block_offset`. Cite file, page, offset, length and the source's digest.

**Encodings**: UTF-8 and UTF-16 (the database's declared byte order) are scanned. CJK, kana, Hangul and emoji in UTF-16 are a lower-confidence reading (they need 8 characters). Text in another encoding, a binary column or an encrypted value is not found.

**Status**: `complete`, `partial` (a time limit, a `-wal` or `-journal` with bytes left unread, pages not examined) or `corrupt` (the file's structure disagreed with itself where `problems` says; fragments found are kept). Check `scanned` and `problems` before writing a negative.

**Filters.** `contains` applies after the scan: `fragments_found_before_filter` says what a filtered run discarded. Keep the unfiltered run's `all_results` file. A filter shows whether text you name is present; it does not read text you do not name.

**Does not show**: a row, a time, an author, or that the page belonged to the table you suspect. Say "recovered text at page N, offset O". Corroborate with the live table, the `-wal`, an app export or another source before a conclusion.

**Sensitive output**: the values file is a sealed output; what you write about it is where it sits and what it is, not what it says.
