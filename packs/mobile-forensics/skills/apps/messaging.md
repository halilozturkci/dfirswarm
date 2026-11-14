---
id: apps/messaging
title: Messaging stores, and what a message row proves
when: A question rests on Messages, SMS, MMS, RCS, WhatsApp, Signal or Telegram records.
needs: []
card: Read the table definitions with sqlite_query {"db_path": "<copy>", "sql": "SELECT sql FROM sqlite_master"} before any row; cite app version and schema. A handle is an address, not a person; sent or received is the app's flag; a read state is not proof anyone looked; a deleted state, a tombstone and a missing row are three findings. An encrypted store is a coverage gap; no key is guessed. plist_read and protobuf_peek show structure, not what a field means. Run a job over a message store with secret_output: true; cite row ids, not content. Does not show: who held the phone, that a message was seen, or that the other party sent what the row says.
tools: [sqlite_query, plist_read, protobuf_peek]
requires_host: []
---

Use when an answer rests on a message store: Apple Messages (`sms.db`), SMS or MMS, RCS, or WhatsApp, Signal and Telegram. Not for choosing the source (`ios/artifacts`, `android/artifacts`) or for deleted content (`apps/databases`).

**Each app is its own family.** Schema, table names and the meaning of a column change between app versions and operating systems (as of November 2026, unverified here). Read the table definitions with `sqlite_query` on a copy before you read a row, and cite the app version and the schema you saw. A parser that names a column does not make the meaning yours.

**What a row can support.** Read these separately and say which you checked:
- Participants: a handle is an address, not a person. Join the conversation, participant and handle tables; do not infer a person from a display name.
- Direction: a column that says sent or received is the app's flag. A synced copy on a second device is not authorship, and an imported or restored message keeps the original's direction.
- State: delivered, read, failed and played are the app's states, with their own times. A read time is not proof the person looked.
- Edits, reactions and unsent messages are separate rows or fields in some versions; a missing edit history is not "never edited".
- Deletion: a deleted state, a tombstone and a missing row are three different findings.
- Attachments: a row names a file; the file may be absent, thumbnail-only or in a cloud store. `media/provenance` covers the file.

**Times** differ per field and per app (`ios/containers-and-time`): keep the raw value and the epoch you chose.

**Encrypted stores.** Signal and similar apps keep their database key outside the file copy. An unreadable database is a coverage gap; no key is guessed.

**Blobs.** A property list in a column is read with `plist_read`; a protobuf with `protobuf_peek` (`ios/biome-segb` shows the window rules). Neither says what a field means.

Shows: what the app recorded about a conversation on this device, under the schema you read.

Does not show: who held the phone, that a message was seen, or that the other party sent what the row says.

Record: app and version, database path and set (`-wal`, `-shm`), schema, the joins you made, the epoch, what you could not read.

Sensitive output: message text and numbers are personal data; run a job over a message store with `secret_output: true` and cite row ids and locations, not content.
