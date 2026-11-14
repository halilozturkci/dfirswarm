---
id: data/browser-storage
title: Browser storage in LevelDB and IndexedDB
when: IndexedDB, Local or Session Storage of a Chromium or Electron app.
card: browser_storage {"path": "<the .leveldb directory>"} first: cite a record by its locator, never by a count. failed with unavailable is no reader, not an empty store; partial names the files not read to their end. A put or a delete is a state at a sequence number, the newest winning, and LevelDB gives no time. Previews withhold only by shape: where secrets matter run it as a secret_output job with {"write_values": true}. Does not show: what a page did with a record, or when it was written.
needs: []
tools: [browser_storage]
requires_host: [ccl_indexeddb_dump]
---

Use when an IndexedDB (`*.indexeddb.leveldb`), Local Storage or Session Storage directory of a Chromium browser or an Electron app may hold the answer. Not for SQLite stores (`data/sqlite`), the HTTP cache (`data/http-cache`), or files that are not LevelDB.

1. Run `browser_storage` on the directory first. It lists databases, object stores, key types and, per store, puts, deletes, distinct keys and `current_keys`. Cite a record by its `locator` (file, offset, sequence number, state), never by a count alone.
2. Read `status`. `failed` with `unavailable` means the `ccl_indexeddb_dump` venv, which holds the reader, is not installed: no inventory was made, and that is not an empty store. `partial` names the files not read to their end, with the problem and its offset (a log cut inside a record, a damaged block); a negative holds for the files that were read. A reader that left a process running after it ended makes it `partial` (`program_group`), with or without `write_values`; with it, so does a host that cannot rule one out.
3. A preview is a lead. Withholding is by shape: a plain password, a word or a short id is printed, and a base64 token of 16 or 20 random bytes is printed in about one preview in five, a 26-character cookie id in about one in eighteen, and a split or UTF-16 token in one in eight to one in fifteen (measured on uniformly random plants; other tokens differ). When secrets matter, run the tool as a `secret_output` job with `write_values`: every record whole in a 0600 file, decoded value and raw bytes. Cite that file and the sequence number, never the value.
4. A put and a delete are states at a sequence number; the newest sequence of a key wins. An older put is an earlier value the files still hold, and a key whose newest record is a delete was removed. No time comes from LevelDB: a Date in a value is the page's own, shown as UTC.
5. Local Storage and Session Storage records are shown as text, not interpreted. Values kept in blob files, and the files' checksums, are not read: a record counted as not decoded is not an empty one.

**Record.** Directory, tool and reader versions, `status`, each cited record's locator, and the store and key as printed.

**Shows.** What the files hold as acquired: names, keys, stored values. **Does not show.** What a page did with them, when a record was written, what the browser would return today, or a record compaction has already removed.

**Sensitive output.** Message, cookie and token stores hold secrets the shape rule cannot see. Run `write_values` in a `secret_output` job; the answer then carries counts and names only.
