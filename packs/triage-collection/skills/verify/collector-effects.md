---
id: verify/collector-effects
title: Collector footprint and chronology
when: Events may be the collector's own, or the order of collection steps matters.
needs: []
tools: [collection_manifest_parse, timestamp_decode]
requires_host: []
---

Use when a conclusion could be confused with the collection itself. Not for the four layers of file time (`verify/time-layers`) or for what a collector copied (`verify/target-outcomes`).

1. Build the chronology from the collector's own records, one interval at a time, each with its clock: deployment (the tool placed), execution (started, ended), collection (per-file copy times), packaging (an archive made), transfer (moved to you). `collection_manifest_parse` keeps the collector's times as raw strings in `times` (a KAPE copy row's `CopiedTimestamp`, its source file's `ModifiedOnUtc`; a Velociraptor row's `started`) and the log lines carry their own. Decode a raw value with `timestamp_decode` and keep the raw text, unit, zone and the basis for the zone.
2. Name what a collector can leave on the source, as hypotheses that depend on the collector, its version and its settings: its binary and archive, files it wrote and removed, access times it updated by reading, execution traces of the tool and what it ran, snapshots it created or used, the response of a security product. State which of these the records support. An absent trace is not an absent footprint: some collectors read raw and update nothing.
3. Compare a window of the data with the collection interval before you set any event aside. An event inside the interval is a candidate footprint to test against independent records (the same moment in another log, the parent process, the account that ran the collector); it is not excluded and not accepted. Never exclude a whole collection window.
4. The delivered files' times and the archive members' times are made later, by the copy and the packaging; they place the delivery, not the collection (`verify/time-layers`).
5. Say what you could not order: two intervals with records on different clocks or no zone are unordered until one record links them.

Shows: when the collector says it did each thing and which events the collector could account for. Does not show: that its clock was right, that it left no other trace, or that an event inside the interval was the collector's.
Record: each interval with its source record and locator, the raw time, zone and basis, the footprint hypotheses and the records that support or contradict each.
Sensitive output: collector records can hold command lines; run `collection_manifest_parse` as a job with `secret_output: true` and cite locators, not strings.
