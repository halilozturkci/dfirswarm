---
id: filesystem/carving
title: Recover candidate structures and validate their limits
when: Relevant data is outside a readable file, or survives only as residual bytes.
needs: [filesystem/extract]
tools: [sig_carve, file_carver, ioc_scan, chunk_needles, feature_scan]
requires_host: [bulk_extractor, photorec, img_cat, icat]
---

Carve by signature, then prove the hit is real before you report it. Every result
here is a candidate: the scanners find where bytes occur, and none shows that the
bytes are a whole, unaltered original file.

**Know the address space first.** `sig_carve`, `file_carver`, `ioc_scan` and
`chunk_needles` read the file you give them as it is. On an E01 or another
container that is the container's bytes, not the disk inside, so an offset from a
scan of the container does not belong to the decoded disk. Decode first
(`img_cat` writes a range of decoded sectors; `evidence/imaging`), or scan an
extracted file or an unallocated-space export. For every candidate keep the
source reference, the byte range, how that address space was defined, the
scanner and its settings, and the sealed output that holds it.

Choose targets from the question and the platform, not by habit. Prefer recovery
that keeps identity and context (the file system's own metadata, snapshots,
backups) before broad carving, when they can answer. `photorec` is an optional
signature-recovery engine for unallocated space, and its output is candidates too.

- `sig_carve` finds where known headers occur, in one pass over the file, and
  returns offsets with a short preview. It estimates no sizes. An unknown
  signature name is an error. A hit is where bytes occur, not a file.
- `file_carver` cuts one candidate at a known offset. Its result says
  `boundary: validated` (a structure walk reached the format's own end) or
  `heuristic` (a header field or marker that was not cross-checked, a PE's section
  table with `overlay_uncertain`). Neither means complete. Validate the candidate
  with a format-aware parser and expected internal lengths, keep the surrounding
  bytes, and report truncation, fragmentation or an unvalidated boundary.
- `ioc_scan` and `chunk_needles` find needles (ASCII and UTF-16LE) and return
  locators: offset, needle, encoding, context length. `chunk_needles` can read an
  inode's stream through `icat`. Every occurrence is kept, so read the whole
  result (`all_results`) and not the inline page.
- `feature_scan` runs `bulk_extractor` over an image or blob: addresses, URLs, card
  numbers, EXIF, telephone numbers, and record scanners (`ntfsmft`, `ntfsindx`,
  `ntfsusn`, `ntfslogfile`, `winprefetch`, `winlnk`, `evtx`) that carve whole
  structures out of unallocated space. It scans the bytes it is given and says
  nothing of allocation status or the original path. Check the installed
  scanner list and which scanners ran (its `report.xml`), and keep its feature
  files, which hold the values. A scanner's name does not guarantee a complete
  record or file.

Work in the order the question sets: the structures that bear on it first, and
among them those that carry time (on Windows prefetch records, event log records,
registry hives and link files; on macOS and iOS property lists and databases; on
Linux journals and logs). For each hit, cut a slice large enough to hold the
record, parse it with the right tool and only then report it; hash every carved
artefact and record where it came from. The offset is part of its provenance, with
the address space it belongs to; there is no path.

A scan with no hit says that these bytes, this signature set and these encodings
produced none. Compressed or encrypted regions, other encodings and a file split
across the range are not found by it. Before a negative is material, record what
was searched, over which range, with which settings, and what was skipped.

Classify candidates by what they bear on, not by filename, signature status or
familiarity: a signed driver or a known installer can still be part of the event
being examined. Say what you did with each, so a reviewer can see you looked.

Text in a memory image is not proof that a process did anything. A string can come
from an antivirus signature file as easily as from a sample. Attribute it to a
process or a mapped region only where memory structures support that mapping;
otherwise report the source image and offset with ownership unknown.

**Does not show.** A hit shows where bytes occur and a validated boundary that a
format's own structure reached its end. Neither shows that a file existed at that
place, was whole, was ever opened or by whom. A string shows that bytes were
there, not who wrote them or what used them.

**Sensitive output.** The bytes around a hit are where passwords, tokens and card
numbers sit. `ioc_scan` and `chunk_needles` return none by default, and
`write_values: true` (in a job, run with `secret_output: true`) writes them to a
sealed file you cite by file and offset, never by value. A needle is recorded in
the trace: never put a secret in one. The files `feature_scan` leaves in `out_dir`
are bulk_extractor's own and hold the values the evidence held (`alerts.txt` can
hold a whole recovery key): the answer says `out_dir_contains_secret_values` and
which kinds hold them, `out_dir` is private, and the job runs with `secret_output: true`.
