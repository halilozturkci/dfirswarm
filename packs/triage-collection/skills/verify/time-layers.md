---
id: verify/time-layers
title: Four timestamp layers in a delivery
when: File times matter, or many files share one date.
needs: []
card: Four clocks: source metadata the collector recorded, times inside the content, archive member times, delivered file times. collection_index {"root": "<collection dir>"} reports only the delivered mtime in UTC; a KAPE pairing's recorded_modified_utc_raw is the collector's unparsed text. collection_timestamps {"root": "<collection dir>", "archive": "<zip or tar>"} reads member times (a zip's DOS time has no zone unless you give local_zone) and compares same-named files only. mtime_distribution_anomaly and apparent_flattening are leads: a time-resetting copy, a bulk write and a real burst look alike. A copy's outer times do not void times inside the file. Does not show: that a time is original.
tools: [collection_index, collection_timestamps]
requires_host: []
mentions: [KAPE]
---

Use when a conclusion rests on a timestamp of a delivered file. Not for decoding a time value (base `timeline/build`).

1. Keep four layers apart: the source file system's metadata (what the collector recorded, if it did), times stored inside the file's content (an event log record, a registry key's last write, a database column), the archive member's metadata, and the metadata of the files you were handed or extracted. They are different clocks with different owners.
2. `collection_index` reports the last layer: `modified` and `modified_epoch_ns` are the delivered file's mtime in UTC, to the nanosecond the file system kept. Where a KAPE copy log pairs a file, its `recorded_modified_utc_raw` is the collector's own text, unparsed, beside it.
3. `collection_timestamps` keeps the archive member's clock (a zip's DOS time: two-second steps, no zone; a tar or pax mtime: UTC) apart from the delivered clock and compares them only for a member and a delivered file of the same name; its `apparent_flattening` is the same one-date count, per clock. `collection_index`'s `mtime_distribution_anomaly` says most files share one UTC date, with the counts. It is a lead. A copy that reset times, one bulk write and a real burst of activity look the same; compare supplied original metadata, the collector's recorded times and the acquisition time before you say which clock you have.
4. A copy that changes a file's outer timestamps does not by itself invalidate event times stored inside the file. Scope any limitation to the fields and objects affected, not to the case.
5. Keep raw value, unit, precision, stated zone and every conversion assumption. Do not apply your own zone to a value with none, or a current offset to a past date without the zone's history.

Shows: which clock a time belongs to. Does not show: that a time is original, that it was or was not preserved, or when a file was really written.
Record: layer, raw value, zone and its basis, what was compared, and the fields affected by any limitation.
Sensitive output: `collection_index` and `collection_timestamps` print paths; run them as jobs with `secret_output: true` and cite a time by its row, never with a credential-shaped path.
