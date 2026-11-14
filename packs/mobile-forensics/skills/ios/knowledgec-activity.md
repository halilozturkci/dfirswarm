---
id: ios/knowledgec-activity
title: KnowledgeC on iOS, and what its events support
when: An activity question depends on an iOS knowledgeC.db or its streams.
needs: []
card: Take knowledgeC.db with its -wal, -shm and -journal as one set. Validate the schema with sqlite_query on a copy first, then knowledgec_query {"db": "<copy>"} (macOS pack, if loaded) for streams and counts; do not carry its presence, retention or stream meanings to iOS. Streams differ by build: a missing legacy stream is not "no activity". Start, end and creation times differ; creation is when the system recorded it. Foreground is not human, and the source can be a synced device. Keep apart not retained, not acquired, unsupported, and searched with no match. Does not show: user actions, presence, or activity outside the retained window.
tools: [knowledgec_query, sqlite_query]
requires_host: []
---

Use when an iOS question depends on `knowledgeC.db`. Not for the macOS store (the macOS pack's `artifacts/knowledgec` and `artifacts/knowledgec-fields-time`, which this note agrees with) or for Biome streams (`ios/biome-segb`).

**Locate and take the set.** On a file-system extraction the store sits under the CoreDuet Knowledge directory of the mobile user; take it with its `-wal`, `-shm` and `-journal` as one set, since committed rows may be only in the log. Which builds still write it, and which streams moved to Biome, differ by iOS version (as of November 2026, unverified here): name the build and look; a missing legacy stream is not "no activity".

**Validate the schema first.** Read the table definitions with `sqlite_query` on a copy before you trust a column: the object table, its stream name, value and source columns, and the times. Then use `knowledgec_query` from the macOS pack, if it is loaded, on that copy for the listing of streams and counts; do not import the macOS pack's claims about presence, retention or stream meaning.

**Times.** A row can carry an event start, an end and a write or creation time, each Apple absolute time (seconds from 2001-01-01 UTC) unless the schema says otherwise (`ios/containers-and-time`). The write time is when the system recorded it, not when the event happened. Keep the raw values.

**What foreground and device-state events support.** An app was recorded in front, the screen was on, the device was locked or plugged in. They do not show input, attention, intent or who held the phone. Foreground is not human. The source column can name another device synced to this one.

**Coverage.** Measure per stream: first and last rows, gaps, rows that did not decode. Keep apart "not retained", "not acquired", "unsupported" and "searched, no match".

Shows: recorded device and app states with the system's times, on this build.

Does not show: user actions, presence, or activity outside the retained window.

Record: build, store and set, schema read, streams used, epoch, gaps.

Sensitive output: app names, bundle ids and domains are in the rows; cite row ids and ranges and run a job over the store with `secret_output: true` when the case treats activity as sensitive.
