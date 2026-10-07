---
id: verify/time-layers
title: Four timestamp layers in a delivery
when: File times matter, or many files share one date.
needs: []
tools: [collection_index]
requires_host: []
---

Use when a conclusion rests on a timestamp of a delivered file. Not for decoding a time value (base `timeline/build`).

1. Keep four layers apart: the source file system's metadata (what the collector recorded, if it did), times stored inside the file's content (an event log record, a registry key's last write, a database column), the archive member's metadata, and the metadata of the files you were handed or extracted. They are different clocks with different owners.
2. `collection_index` reports the last layer: `modified` and `modified_epoch_ns` are the delivered file's mtime in UTC, to the nanosecond the file system kept. Where a KAPE copy log pairs a file, its `recorded_modified_utc_raw` is the collector's own text, unparsed, beside it.
3. `mtime_distribution_anomaly` says most files share one UTC date, with the counts. It is a lead. A copy that reset times, one bulk write and a real burst of activity look the same; compare supplied original metadata, the collector's recorded times and the acquisition time before you say which clock you have.
4. A copy that changes a file's outer timestamps does not by itself invalidate event times stored inside the file. Scope any limitation to the fields and objects affected, not to the case.
5. Keep raw value, unit, precision, stated zone and every conversion assumption. Do not apply your own zone to a value with none, or a current offset to a past date without the zone's history.

Shows: which clock a time belongs to. Does not show: that a time is original, that it was or was not preserved, or when a file was really written.
Record: layer, raw value, zone and its basis, what was compared, and the fields affected by any limitation.
Sensitive output: `collection_index` prints paths; run it as a job with `secret_output: true` and cite a time by its row, never with a credential-shaped path.
