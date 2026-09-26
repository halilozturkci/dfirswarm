---
id: ios/biome-segb
title: Biome and SEGB streams without false timestamps
when: Activity, location, device-state or app events are in an iOS Biome stream.
needs: [ios/artifacts]
tools: []
requires_host: [ileapp]
---

Biome is a collection of named streams, commonly under
`private/var/mobile/Library/Biome/streams/`. Its stream files are SEGB
containers. SEGB is not itself protobuf: it frames records, records their
state and carries its own write timestamp; a framed payload may then be a
protobuf, plist or another stream-specific structure.

Run iLEAPP over the extraction and retain the exports for the individual Biome
modules. Prefer a module named for the stream over a schema-less decode. Use
`protobuf_peek` only on a payload already separated from its SEGB frame, and
label every inferred field because field names do not exist without a schema.

For every cited record keep four things together: stream name, source file,
byte offset and SEGB state. `Deleted` is a record state, not proof of when the
user deleted an event. Tombstone files describe retired stream storage and
must not automatically be presented as user events.

Do not equate the SEGB timestamp with the event time. It is generally the
record write/harvest time; stream payloads may carry their own start, end or
event time. A defensible timeline says which timestamp it used and preserves
both when they differ.
