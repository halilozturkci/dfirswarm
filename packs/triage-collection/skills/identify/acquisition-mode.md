---
id: identify/acquisition-mode
title: Live, mounted, snapshot or earlier: what was read
when: Time, consistency or collector contamination of a file matters.
needs: []
tools: [collection_id]
requires_host: []
---

Use when time, consistency or contamination of a collected file matters. Not for identifying the collector (`identify/collector`) or checking its manifest (`verify/manifests`).

1. Establish what the collector read: a running host, a mounted image, a snapshot, or an earlier collection. The records and the operator's account say; the file names do not.
2. A collection of a running host takes time while the system keeps writing. Files copied at different moments need not describe one state, so two artefacts may disagree with neither wrong. Quote the overall interval and any per-item times the records give (`collection_id` prints none: read the copy log's own time columns by hand).
3. Keep four times apart, each with its zone and uncertainty: the source's time, a snapshot's time, the collection time and any later processing time. Do not give an unknown-zone value your own zone.
4. Collector-created processes, files, logs and access times are a contamination hypothesis until the acquisition records corroborate them. Keep activity that overlaps the collection window in the case: do not call it benign because it overlaps, and do not exclude the whole window.
5. A collection from a mounted image or a snapshot can carry the image's or snapshot's moment, not the collector's; a derived or re-packaged collection adds its own processing times.

Shows: which moment or moments the files can speak for, and what the collector may have added. Does not show: the cause of an inconsistency between two files, or that an event outside the interval did not happen.
Record: the mode and its basis, the interval with zones, the time layers you could and could not establish, and any collector footprint you hypothesised with what would corroborate it.
Sensitive output: a collector's own command lines are in its logs; run `collection_id` as a job with `secret_output: true` and quote locators.
