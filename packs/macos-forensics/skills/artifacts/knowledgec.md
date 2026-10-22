---
id: artifacts/knowledgec
title: KnowledgeC activity records and their limits
when: Interpret retained application and device-state activity.
needs: []
tools: [knowledgec_query, sqlite_query]
requires_host: []
---

Use when you read macOS application or device-state activity from `knowledgeC.db`. Not for a row's columns, values and dates (`artifacts/knowledgec-fields-time`, only if you read them).

macOS keeps application and device-state records for its own features in SQLite: what those features saw, not a log of what a person did.

    ~/Library/Application Support/Knowledge/knowledgeC.db     per user
    /private/var/db/CoreDuet/Knowledge/knowledgeC.db          system-wide

Inventory the user and system stores separately; take each database with its `-wal`, `-shm` and `-journal` as one set. A write-ahead log holds committed rows the main file lacks: `knowledgec_query` applies one in a private copy and counts the frames (`source_used`); a log left behind at collection is rows you do not have. A rollback journal holds old pages of a transaction that did not commit, no rows the main file lacks; a hot one is rolled back in the copy and `problems` says so (the copy is then not the main file as acquired).

**Enumerate before you query.** The answer lists the streams with their count and first and last start (2,000 at most; `streams_not_listed` counts the rest); streams, field types and retention vary by build. Check `status`, `problems` and `filters_unapplied`; a `partial` read has a `resume` (`artifacts/knowledgec-fields-time`). For another table or query use `sqlite_query` on a copy, and read what it says about the write-ahead log before you rely on a negative.

**Whose activity.** The `source` columns can name a device other than this Mac: decide whether the source identifies this device before you attribute a row to it.

**What foreground and display records support.** Shows: recorded state (this application was in front, the screen was lit, the device was locked). Does not show: keyboard input, physical presence, attention, intent or who the human was. Correlate authentication and session evidence (`logs/unified`, `accounts/users`) and weigh remote access first.

**Biome.** `~/Library/Biome/` holds another format (SEGB frames) that this pack has no decoder for; the mobile pack's `ios/biome-segb`, if loaded, separates framing from payload, and iOS semantics do not carry over. A gap here is not absence elsewhere.

**Coverage.** Measure it per stream and source: first and last rows, gaps, decoding failures, sidecars present. Cite the database, table, `z_pk`, query and sealed output; keep apart "not retained", "not acquired", "unsupported" and "searched, no match".

**Sensitive output.** Every string of an entry (a BLOB's head as hexadecimal) passes the shared boundary: a token-shaped value, user-info or the value after a secret's name is shown as `<withheld N characters: reason>`. That is by shape: a plain password, a passphrase, a UUID-shaped key, a BitLocker key or anything under 16 characters in a name is printed. `/safari/history` and web-usage values are URLs that can carry tokens: write one without its query. Read a database whose values matter as a job with `secret_output: true`; `write_values` there puts the originals in a private file under `$OUT`. Cite the row and the file, never a value, a fragment or a hash of one.
