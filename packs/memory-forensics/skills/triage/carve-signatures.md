---
id: triage/carve-signatures
title: Carving structures from an image by signature
when: Using mem_carve or sig_carve to find hives, event logs, Prefetch or PE headers in a raw image.
needs: []
tools: [mem_carve, sig_carve]
requires_host: []
---

Use only if you run `mem_carve` or `sig_carve` over an image. Not for deciding whether to examine without a framework (`triage/no-framework`).

**`mem_carve`** finds configured byte signatures in the file and can save a
slice at each (the kind's fixed size, or the length the header declares up to a cap): registry hives (`regf`), event log chunks and files,
Prefetch records (plain `SCCA`, and compressed `MAM\x04`), PE headers, SQLite
databases, MFT and index records, zip, PDF and property lists. It does not
rebuild a fragmented file, decompress hibernation data or parse paging structures.
Each hit has a `signature_offset`, an `object_offset` where the structure starts
(a plain Prefetch record starts four bytes before `SCCA`; null when that is not
established) and a `validation` (header plausible, implausible, truncated or only
a signature; truncated means the file itself ends first, and `cut_complete: false`
means the slice is shorter than the declared length, not that the image is cut). Offsets are offsets in the file, and the offsets are the whole
provenance: there is no path. Record the signatures selected, the interval
searched, the hit count, the extraction limit (default 25, at most 1,000, earliest hits first)
and how many hits were not extracted. The sweep has its own clock (`max_seconds`, default
600; slices cut out count toward `max_results_bytes`): when it stops the answer is partial and `coverage.resume_start` is the `start` for
the rest, and each call moves it forward; bound a very large image with `start` and `max_bytes`. A slice can start inside a structure, end
before it finishes or run into unrelated adjacent pages: check its start, its
declared length and its internal consistency before you choose a parser, and
treat a successful parse as evidence about the records it validated.
`sig_carve` reports a signature the same way: for a plain Prefetch record, where
`SCCA` is, not where the structure begins.

**Sensitive output.** The hit list (offsets, kinds, validation) is not secret. A slice is memory content and can be a credential store (a SAM or SECURITY hive, a browser database), so `extract_to` needs `write_values: true` in a job run with `secret_output: true` (the manifest declares it), and is refused as JSON anywhere else. Credential hives are cut on purpose; a cracking tool downstream stays available. Cite slices by job reference and offset, never by content.

**Does not show.** That a signature hit is a whole, readable file; that a parse of a slice describes the original structure; that no hits means the structure is absent.
