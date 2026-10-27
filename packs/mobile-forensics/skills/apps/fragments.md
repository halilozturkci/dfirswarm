---
id: apps/fragments
title: Reading a sqlite_freespace answer
when: You ran sqlite_freespace and must report what its fragments are.
needs: []
tools: [sqlite_freespace]
requires_host: []
---

Use only if you ran `sqlite_freespace` and must report what its fragments are. Not for deciding whether to run it (`apps/databases`).

**The text is withheld.** The answer gives, per fragment: `finding_id`, page, `where` (freelist trunk or leaf page, unallocated space in page, freeblock in page, page beyond the declared size), byte `offset`, `bytes`, `characters`, `encoding`. The text itself is written only on `write_values: true`, in a job run with `secret_output: true`, to `$OUT/sqlite-freespace-values.jsonl` (mode 0600); outside a job the request is refused. Read that file in the job; do not paste values into a post or the ledger.

**Offsets** are file byte positions, read back and compared (`offset_verified`). A freeblock fragment starts after the freeblock's 4-byte header and carries `block_offset` (within its page). Cite file, page, offset, length, digest.

**Encodings**: UTF-8 and UTF-16 (the database's declared byte order) are scanned. CJK, kana, Hangul and emoji in UTF-16 are a lower-confidence reading (they need 8 characters). Text in another encoding, a binary column or an encrypted value is not found.

**Status**: `complete` (every page accounted for: b-tree, free or overflow), `partial` (a time limit, a `-wal` or `-journal` with bytes left unread, pages not examined) or `corrupt` (the file's structure disagreed with itself where `problems` says; fragments found are kept). Pages no structure owns, as when the header's freelist fields were zeroed, are read as free space (`page in no structure`) and make it `corrupt`. Check `scanned` and `problems` before writing a negative.

**Filters.** `contains` needs `write_values` and only marks the rows of the values file: every fragment is a row, `match` is 1 (matched), 0 or 2 (not decided in time, and the status is partial); filter on `match` when you read the file. The answer lists every fragment and does not say which matched or how many. It is accepted only as an expression of bounded cost: no `*`, `+` or `{m,}` (write `{1,64}`), no nested repeat, lookaround or back reference, at most 256 characters and 256 steps; its run time can say that much of the free space is of a class the expression matches, not the answer: the work budget is in sizes the answer shows, and a fragment past it is `match` 2 and makes the status partial. An `all_results` file the answer names is the whole list (millions, for repeated short text).

Shows: that text of a stated encoding sat at a stated offset of a stated page of the file.

Does not show: a row, a time, an author, or that the page belonged to the table you suspect. Say "recovered text at page N, offset O". Corroborate with the live table, the `-wal`, an app export or another source before a conclusion.

Record: file and its digest, page, offset, length, encoding, the status and any `problems` that applied.

Sensitive output: the values file is a sealed output; what you write about it is where it sits and what it is, not what it says. It lies under `store/`, which your VM mounts read-only, so you can open it: the tool's measures guard the answer and the file's size and digest, not an agent that reads the file. Open it only for what the task needs.
