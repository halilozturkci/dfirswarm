---
id: normalise/layout
title: Source path, delivered path and analysis path
when: Before you cite a delivered file by path.
needs: [identify/collector]
tools: [collection_index]
requires_host: []
---

Use when you cite or interpret a path from a delivery. Not for deciding whether the census is complete or which parser fits.

1. Keep three identities apart: the **source path** the collector recorded, the **delivered path** (container member or file in the tree you were handed) and the **analysis path** you extracted to. They may differ, and not every collector rewrites. Look for drive or volume roots, accessor prefixes, named streams, reserved names, long paths, encodings, Unicode normalisation and case collisions. A colon is handled by the naming layer and the file system the file passed through. An underscore or a dot in a name does not show a renamed stream, and a missing stream cannot be diagnosed from the extracted name.
2. `collection_index` gives, per file, `source_path_hypothesis`: a convention's reading with its `method`, `confidence` (low, medium or none), `unresolved_components` and `alternatives`. It is a guess about a layout. `source_path_observed` is filled only from a KAPE copy log in the tree, with the log and row; two matching rows are `ambiguous`, and the other collectors' records are not read.
3. Do not strip a leading `root`: it may be the source's `/root`, and the tool keeps it with the wrapper reading as an alternative. Do not read accessor or wrapper components (`uploads`, `auto`, a drive spelled `C%3A`) as source directories without the collector's index. Do not reverse an apparent stream rename without a mapping (`possible_renamed_streams` is a guess from name shape).
4. Cite the delivered input or the sealed job object and its member locator or relative path. Add the source path, host, volume, snapshot or stream only where a mapping row supports it, and say which. Where it is uncertain write "source path unresolved" and keep the delivered locator. Never rename evidence in place, and never merge two entries because their displayed paths normalise alike.

Only if you will quote a file count or say a file is not in the delivery: `normalise/inventory`. Only if a delivered file is going to a parser: `normalise/parsers`.

Shows: where a file sits in what you were given, and what a convention or a collector's row says it was. Does not show: the source path of a file with no row, or that a stream was dropped or renamed.
Record: delivered path and hash, the hypothesis with its confidence or the observed path with its log row, and what is unresolved.
Sensitive output: `collection_index` prints paths and digests; run it as a job with `secret_output: true`, never copy a credential-shaped path or the digest of a file that is itself a secret into a finding.
