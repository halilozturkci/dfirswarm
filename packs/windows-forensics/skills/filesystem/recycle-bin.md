---
id: filesystem/recycle-bin
title: Recycle Bin $I records
when: You need the original path, size and time of items sent to the Recycle Bin.
needs: [filesystem/deleted]
tools: [recyclebin_i, usn_journal]
requires_host: []
---

Use when you read `$Recycle.Bin` metadata. Not for deleted records in general (`filesystem/deleted`) or the change journal (`filesystem/journals`).

- `$Recycle.Bin\<SID>\` holds a `$I` metadata file and a `$R` content file per item. Extract the `$I` files from the image (a deleted `$I` whose record survives can be read like any deleted file) into a directory that keeps the SID as its name, and run `recyclebin_i` over one `$I` or the directory (sorted). Version 1 (544 bytes) and version 2 (a character count, then the path) are read.
- An entry gives `original_path`, `original_size`, `deleted_at` (seven digits, raw FILETIME beside), `bin_directory_sid` (from the directory name) and `r_file`, which names the `$R` counterpart only if you extracted it into the same directory. Pair each `$I` with its `$R` by their shared identifier, and record the `$R` in the image (present, size against the `$I`, record allocated or not) whether or not `r_file` found it.
- Read `status` and the counts before an entry: `truncated` (with `trailing_bytes`; `records_truncated` counts) is a record shorter than its layout, returned with the path decoded as far as it goes and never a complete path; a file over 1 MiB is not read; `unknown_header` is not guessed at; `unreadable` is counted. A `$I` that is a link, FIFO, device, socket or directory is not opened and is listed with a reason (`not_attempted`, partial), and the rest of the bin is still read.
- The SID is the account whose bin received the item. It does not say who deleted the file, from which session or program, or from where. Corroborate with the rename into the bin and the later `FILE_DELETE` in `usn_journal` (`filesystem/journals`) and with session evidence (`accounts/sessions`).
- The deletion time is when the item went to the bin, on the clock that wrote it. It is not when the bin was emptied. No `$I` does not show the file was not deleted: a deletion that bypasses the bin, a disabled bin or an emptied one (its `$I` records may survive as deleted entries) leaves no live one.

Shows: this account's bin received an item with this path and size at this time. Does not show: who deleted it, that it was deleted rather than moved out, or where the content is now. Record: the `$I` and its record, SID, `$R` state, the truncation and not-attempted counts, the corroboration you looked for.
