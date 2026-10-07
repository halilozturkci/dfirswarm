---
id: ios/biome-segb
title: Biome and SEGB records by format and stream
when: Use when an activity question depends on an iOS Biome or other SEGB stream. Not for KnowledgeC or unified logs.
needs: [ios/artifacts]
tools: [protobuf_peek]
requires_host: [ileapp]
---

Use when an activity question depends on an iOS Biome or other SEGB stream. Not for KnowledgeC (a SQLite store: `ios/artifacts`) or the unified log (`ios/unified-logs`).

**Inventory** the Biome and SEGB sources (commonly `mobile/Library/Biome/streams/`): stream metadata, local and other acquired stream directories, tombstone files. A directory name does not say which device wrote a record.

**Identify the SEGB version** from the source and the parser. Unsupported framing is a parser limit, not an empty stream. SEGB frames records and carries its own timestamp; the payload may be protobuf, plist or another structure.

**Parse** with the stream-named `ileapp` module, after checking that the release supports the stream and format; keep its output and logs. For a material event keep stream, source file, record or payload offset where the module gives it, raw state, format version and module version. If the module gives no locator, say the record-level locator is unresolved; never invent an offset from report order.

**Schema-less payload.** Run `protobuf_peek` only on a payload already cut from its frame. Its answer is wire structure: field numbers, wire types, offsets, top-level varints. It does not say field names, units, signedness or event meaning, and it withholds string and byte content (a job with `secret_output: true` and `write_values: true` writes them to a sealed file). Label every inference.

**Times.** Keep the container timestamp and the payload's own times apart, with raw values and precision. Do not call a container time the event or harvest time without the stream's format saying so.

**Deleted state or tombstone**: record lifecycle of storage, not proof that a person deleted an event, when, or that the payload records a completed action.

**Does not show**: a person acting, or the full activity of the device. Corroborate with app records, KnowledgeC where present or a diagnostic record. A negative states the streams present, the parser failures, retention gaps and duplicates checked.

**Sensitive output**: Biome payloads can hold message text, URLs and identifiers: run payload readers as a job with `secret_output: true`.
