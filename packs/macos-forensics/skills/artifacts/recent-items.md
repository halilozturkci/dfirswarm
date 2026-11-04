---
id: artifacts/recent-items
title: Recent items, shared file lists and bookmarks
when: A question is which files, folders, applications or sites a user opened recently.
needs: []
tools: [plist_read, macos_login_items, safari_history]
requires_host: []
---

Use when a question rests on recent-item lists, shared file lists, bookmarks or aliases, application MRUs or browser history. Not for plain plist reading (`artifacts/plists`) or for keyed-archive and date rules (`artifacts/plists-archives-dates`, only if).

**Sources.** The sources are different formats with different limits:
- SharedFileList archives (`.sfl`, `.sfl2` and later, under the user's `Library/Application Support/com.apple.sharedfilelist/`): NSKeyedArchiver graphs of recent documents, applications, servers and favourites. `plist_read` shows their structure; it does not resolve the references.
- Bookmarks and aliases inside them or in preferences: binary data. `plist_read` shows no binary value, so the path inside is not read; a decoder for them must be named, version-checked and validated before its output is cited. `macos_login_items` resolves background-item archives only, and shows a bookmark by length alone.
- Application MRUs: each application keeps its own list in its preferences property list, under keys it names itself. There is no standard key; read the schema from the file.
- Browser history: Safari's `History.db` with `safari_history` (visits, Apple absolute times). Other browsers are other stores.

**Reading a list.** Keep the list's order as stored; an entry carries a time only if the field says so. A list is capped and rewritten, so an old item is gone because the list turned over, not because it never existed. The file's modified time is the last rewrite of the whole list, not the time of any entry.

**A stored reference is not an open.** An entry shows that a file was referenced, with the path or identifier the application stored at that moment: not that the content was opened, who opened it, that it still exists, or when. A bookmark can point at a volume that was never acquired. Corroborate with the application's own records, `artifacts/fsevents` or the unified log (`logs/unified`).

**Coverage.** Name the users and applications whose lists were acquired, and each list's schema; "searched, no match" is bounded by them.

Shows: that a path or site was recorded in a user's list, in the stored order. Does not show: that it was opened, when, what was read, or that an item absent from the list was never used.
Record: the file, its modified time, the key or archive path of the entry, the decoder and its version, the references left unresolved, raw values with the epoch assumed.
Sensitive output: file names, paths and URLs can name people or carry tokens. `safari_history` withholds URL query values by shape, and a plain secret is printed; run a store whose values matter as a job with `secret_output: true` and cite the entry, never a value.
