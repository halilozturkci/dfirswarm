---
id: artifacts/fsevents-dating
title: Ordering and dating FSEvents records
when: Order FSEvents records, date one, read its flags, or use an external volume's log.
needs: []
card: fsevents_parse event ids order records within one volume's continuous history; they do not date them, and a record has no timestamp. Never compare ids across volumes or a restored history. Dating needs a matching operation with an independent time on each side; one anchor bounds one side only. A Renamed flag gives neither name nor the actor. Does not show: a date from an id, the actor, or which Mac an external volume's log belongs to.
tools: [fsevents_parse]
requires_host: []
---

Use only if the question needs the order of FSEvents records, a date for one, the meaning of its flags, or an external volume's log. Not for what the parser read or the log's coverage (`artifacts/fsevents`).

**Event ids (printed by `fsevents_parse`) order records; they do not date them.** The counter belongs to one volume's log. Compare ids within one continuous history, never across volumes or across a restored history, and keep the evidence of gaps, resets and collection boundaries. There is no timestamp in the record.

**Dating a record takes two anchors.** A file with the same path and a known time does not make the event dated. Find an operation that matches (same path and kind of change) with an independent time from another artefact, before and after the id in question within the same history, and state the matching assumption and the clock uncertainty. One anchor bounds the interval on one side; it does not date every neighbouring id.

**Flags.** Many changes to a path can collapse into one record with the flags accumulated. A `Renamed` flag means the path took part in a rename; it does not give the old and the new name, the destination or the actor. Repeated paths, hard links, directory events and reused file ids complicate matching: corroborate with filesystem metadata, snapshots (`filesystem/apfs`) and other retained records.

**An external volume's log travels with the volume.** It shows changes on that volume and their order. It names a Mac only with a machine-specific record beside it, such as a mount, device or unified-log entry (`logs/unified`).

Shows: the order of records within one history, and a path's recorded change kinds. Does not show: a date from an id, the old and new name of a rename, the actor, or which Mac an external volume's log belongs to.
Record: the anchors and their sources, the matching assumption, the clock uncertainty, the gaps and resets.
