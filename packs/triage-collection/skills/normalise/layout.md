---
id: normalise/layout
title: Source path, delivered path and analysis path
when: Before you cite a delivered file by path.
needs: [identify/collector]
card: collection_path_map {"root": "<dir>"} labels a file observed (a record names it), ambiguous or hypothesis_only; collection_index's source_path_hypothesis is a guess. Else write "source path unresolved" and cite the delivered locator. Does not show: an unrecorded source path.
tools: [collection_index, collection_path_map]
requires_host: []
mentions: [KAPE]
---

Use when you cite or interpret a path from a delivery. Not for census completeness or parser choice.

1. Keep three identities apart: the **source path** the collector recorded, the **delivered path** (container member or file handed to you) and the **analysis path** you extracted to; not every collector rewrites. Watch for drive or volume roots, accessor prefixes, named streams, reserved names, long paths, encodings, Unicode normalisation and case collisions. A colon's fate depends on the naming layer and file systems it passed through. An underscore or dot in a name does not show a renamed stream, nor an extracted name a missing one; a collector may drop named streams altogether, so a delivery without them says nothing of the source's.
2. `collection_index` gives, per file, `source_path_hypothesis`: a convention's guess about a layout, with its `method`, `confidence` (low, medium or none), `unresolved_components` and `alternatives`. `source_path_observed` is filled only from a KAPE copy log in the tree, with log and row, matched on the path relative to the log's directory (rows naming different sources, or a sibling sharing the name, are `ambiguous`, every candidate listed; `recorded_modified_utc_raw` and `recorded_file_size_raw` are the collector's text). `collection_path_map` observes source paths from KAPE, Velociraptor and UAC records, says how each joined its file, and keeps a hypothesis beside, never as, an observation.
3. Do not strip a leading `root`: it may be the source's `/root` (the tool keeps the wrapper reading as an alternative). Do not read accessor or wrapper components (`uploads`, `auto`, a drive spelled `C%3A`) as source directories without the collector's index. Do not reverse an apparent stream rename without a mapping (`possible_renamed_streams` guesses from name shape).
4. Cite the delivered input or sealed job object with its member locator or relative path. Add the source path, host, volume, snapshot or stream only where a mapping row supports it, and say which. If unsure write "source path unresolved", keeping the delivered locator. Never rename evidence in place, or merge entries whose displayed paths normalise alike.

Only if you will quote a file count or say a file is not in the delivery: `normalise/inventory`. Only if a delivered file is going to a parser: `normalise/parsers`.

Shows: where a file sits in the delivery, and what a convention or a collector's row says it was. Does not show: the source path of a file with no row, or that a stream was dropped or renamed.
Record: delivered path and hash, the hypothesis and confidence or the observed path and log row, and what is unresolved.
Sensitive output: `collection_index` prints paths and digests; run it as a job with `secret_output: true`, never copy a credential-shaped path or the digest of a file that is itself a secret into a finding.
