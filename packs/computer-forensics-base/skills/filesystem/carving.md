---
id: filesystem/carving
title: Recover candidate structures and validate their limits
when: Data is outside a readable file, or only residual bytes.
needs: []
tools: [sig_carve, file_carver]
requires_host: [photorec, img_cat]
---

Use when relevant data is outside any readable file or survives only as residual bytes. Not for a record the listing names (`filesystem/extract`). Needle and feature scans, the order of work and classifying candidates: `filesystem/scanners`.

Carve by signature, then prove the hit is real before you report it. Every result here is a candidate: the scanners find where bytes occur, and none shows that the bytes are a whole, unaltered original file.

**Know the address space first.** `sig_carve` and `file_carver` read the file you give them as it is. On an E01 or another container that is the container's bytes, not the disk inside, so an offset from a scan of the container does not belong to the decoded disk. Decode first (`img_cat` writes a range of decoded sectors; `filesystem/layers`), or scan an extracted file or an unallocated-space export. For every candidate keep the source reference, the byte range, how that address space was defined, the scanner and its settings, and the sealed output that holds it.

Choose targets from the question and the platform, not by habit. Prefer recovery that keeps identity and context (the file system's own metadata, snapshots, backups) before broad carving, when they can answer. `photorec` is an optional signature-recovery engine for unallocated space, and its output is candidates too.

- `sig_carve` finds where known headers occur, in one pass over the file, and returns offsets with a short preview. It estimates no sizes. An unknown signature name is an error. A hit is where bytes occur, not a file.
- `file_carver` cuts one candidate at a known offset. Its result says `boundary: validated` (a structure walk reached the format's own end) or `heuristic` (a header field or marker that was not cross-checked, a PE's section table with `overlay_uncertain`). Neither means complete. Validate the candidate with a format-aware parser and expected internal lengths, keep the surrounding bytes, and report truncation, fragmentation or an unvalidated boundary.

For each hit, cut a slice large enough to hold the record, parse it with the right tool and only then report it; hash every carved artefact and record where it came from. The offset is part of its provenance, with the address space it belongs to; there is no path.

A scan with no hit says that these bytes, this signature set and these encodings produced none. Compressed or encrypted regions, other encodings and a file split across the range are not found by it. Before a negative is material, record what was searched, over which range, with which settings, and what was skipped (`evidence/coverage`).

**Does not show.** A hit shows where bytes occur and a validated boundary that a format's own structure reached its end. Neither shows that a file existed at that place, was whole, was ever opened or by whom.

**Sensitive output.** The bytes around a hit are where passwords, tokens and card numbers sit. Cite a carved artefact by source, offset and length; for a candidate that may be a credential store or key, run the job with `secret_output: true` and record where it sits, its kind and its length.
