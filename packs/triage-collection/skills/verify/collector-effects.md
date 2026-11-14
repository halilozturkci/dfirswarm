---
id: verify/collector-effects
title: Collector footprint and chronology
when: Events may be the collector's own, or the order of collection steps matters.
needs: []
card: collection_timestamps {"root": "<collection dir>"} gives the acquisition interval from each collector log's first and last timestamped line, or unknown (never from file times); a KAPE CopiedTimestamp states no zone. timestamp_decode decodes a number only: keep raw text, unit and zone basis. An event inside the interval is a candidate footprint to test, neither excluded nor accepted. Does not show: that the collector's clock was right.
tools: [collection_manifest_parse, timestamp_decode, collection_timestamps]
requires_host: []
mentions: [KAPE]
---

Use when a conclusion could be confused with the collection itself. Not for file-time layers (`verify/time-layers`) or what was copied (`verify/target-outcomes`).

1. Build the chronology from the collector's own records, one interval at a time, each with its clock: deployment (the tool placed), execution (started, ended), collection (per-file copy times), packaging (an archive made), transfer (moved to you). `collection_manifest_parse` keeps the collector's times as raw strings in `times` (a KAPE copy row's `CopiedTimestamp`, its source file's `ModifiedOnUtc`; a Velociraptor row's `started`) and log lines carry their own. Decode a number with `timestamp_decode`; keep the raw text, unit, zone and its basis. `collection_timestamps` keeps these as the collector's text, each with the zone its writer states and the basis (a KAPE `CopiedTimestamp` states none, so it is a wall-clock reading), gives each collector log's first and last timestamped line as the acquisition interval, or `unknown` (never from file times), and compares a copy row's `ModifiedOnUtc` with the delivered mtime only where the join names one file.
2. Name what a collector can leave on the source, as hypotheses depending on collector, version and settings: its binary and archive, files it wrote and removed, access times it updated by reading, execution traces of the tool and what it ran, snapshots it created or used, the response of a security product. Say which the records support. An absent trace is not an absent footprint: some collectors read raw and update nothing.
3. Compare a data window with the collection interval before setting any event aside. An event inside the interval is a candidate footprint to test against independent records (the same moment in another log, the parent process, the account running the collector); neither excluded nor accepted. Never exclude a whole window.
4. Delivered file and archive member times are made later, by copy and packaging; they place the delivery, not the collection (`verify/time-layers`).
5. Two intervals on different clocks or with no zone stay unordered until a record links them: say so.

Shows: when the collector says it did each thing and which events it could account for. Does not show: that its clock was right, that it left no other trace, or that an event inside the interval was the collector's.
Record: each interval with its source record and locator, the raw time, zone and basis, the footprint hypotheses and the records that support or contradict each.
Sensitive output: records hold command lines; run `collection_manifest_parse` as a job with `secret_output: true` and cite locators, not strings.
