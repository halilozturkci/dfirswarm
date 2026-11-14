---
id: triage/carve-signatures
title: Carving structures by signature
when: Using mem_carve or sig_carve to find hives, event logs, Prefetch or PE headers in an image.
needs: []
card: mem_carve {"path": "<image>", "kinds": ["registry hive"]}: read status first; partial gives coverage.resume_start for the rest. Offsets are file offsets, the only provenance. cut_complete false: the slice is shorter than declared, not a cut image. sig_carve gives the signature, not the start (object_offset). Slices: {"write_values": true} in a secret_output job. Does not show: a whole file, or absence from no hits.
tools: [mem_carve, sig_carve, carve_handoff]
requires_host: []
---

Use only if you run `mem_carve` or `sig_carve` over an image. Not for deciding whether to examine without a framework (`triage/no-framework`).

**`mem_carve`** finds configured byte signatures in the file and can save a
slice at each (the kind's fixed size, or the length the header declares up to a cap): registry hives (`regf`), event log chunks and files,
Prefetch records (plain `SCCA`, and compressed `MAM\x04`), PE headers, SQLite
databases, MFT and index records, zip, PDF and property lists. It does not
rebuild a fragmented file, decompress hibernation data or parse paging structures.
Each hit has a `signature_offset`, an `object_offset` where the structure starts
(a plain Prefetch record: four bytes before `SCCA`; null when not established) and a `validation` (header plausible, implausible, truncated or only
a signature; truncated means the file itself ends first, and `cut_complete: false`
means the slice is shorter than the declared length, not that the image is cut). Offsets are file offsets and the whole
provenance: there is no path. Record the signatures selected, the interval
searched, the hit count, the extraction limit (default 25, at most 1,000, earliest first)
and how many hits were not extracted. The sweep has its own clock (`max_seconds`, default
600; slices cut out count toward `max_results_bytes`): when it stops the answer is partial and `coverage.resume_start` is the `start` for the rest; bound a very large image with `start` and `max_bytes`. A slice can start inside a structure, end early or run into unrelated pages: check
its start, declared length and internal consistency before choosing a parser; a
successful parse is evidence about the records it validated.
`sig_carve` gives the signature's place too: for plain Prefetch, `SCCA`, not the
structure's start.

`carve_handoff` takes one hit (`kind`, `signature_offset`) and readies it for its parser: the start by that rule, the cut, the header checks and, for a hive or an event log file, whether its bins or chunks stay adjacent in the image. It hashes a slice only for a family that cannot be a credential store.

**Sensitive output.** The hit list is not secret. A slice is memory content and can be a credential store (a SAM or SECURITY hive, a browser database), so `extract_to` (and `carve_handoff`'s slice) needs `write_values: true` in a job run with `secret_output: true`, and is refused anywhere else. Credential hives are cut on purpose; a cracking tool downstream stays available. Cite slices by job reference and offset, never by content.

**Does not show.** That a signature hit is a whole, readable file; that a parse of a slice describes the original structure; that no hits means the structure is absent.
