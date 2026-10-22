---
id: filesystem/scanners
title: Needle and feature scans over raw bytes
when: Searching an image, blob or unallocated export for strings or record types, not a known header.
needs: []
tools: [ioc_scan, chunk_needles, feature_scan]
requires_host: [bulk_extractor, icat]
---

Use only if you scan bytes for needles or features (`filesystem/carving` says when). Not for cutting one candidate at a known offset (`filesystem/carving`).

The address-space rule of `filesystem/carving` holds: these tools read the file you give them, so decode a container first and keep the address space with every offset.

- `ioc_scan` and `chunk_needles` find needles (ASCII and UTF-16LE) and return locators: offset, needle, encoding, context length. `chunk_needles` can read an inode's stream through `icat`. Every occurrence is kept, so read the whole result (`all_results`) and not the inline page. Counts are of the window scanned (`scanned_start` to `scanned_end`); bound a large image with `start` and `length`. A scan that reaches its clock (`max_seconds`, 100; cost is needles times bytes) says `status: partial` and `next_start`: go on from there.
- `feature_scan` runs `bulk_extractor` over an image or blob: addresses, URLs, card numbers, EXIF, telephone numbers, and record scanners (`ntfsmft`, `ntfsindx`, `ntfsusn`, `ntfslogfile`, `winprefetch`, `winlnk`, `evtx`) that carve whole structures out of unallocated space. It scans the bytes it is given and says nothing of allocation status or the original path. Check which scanners ran (`report.xml`) and keep its feature files. A scanner's name does not guarantee a complete record.

**Order.** Work in the order the question sets: structures that bear on it first, those that carry time (prefetch, event logs, hives and link files on Windows; property lists and databases on macOS and iOS; journals and logs on Linux). Cut a slice that holds the record, parse it, and only then report it.

**Classify** candidates by what they bear on, not by filename, signature or familiarity: a signed driver or known installer can still be part of the event.

**Text in a memory image** is not proof that a process did anything: a string can come from an antivirus signature file as easily as from a sample. Attribute it to a process or a mapped region only where memory structures support that mapping; otherwise report the source image and offset with ownership unknown.

**Negatives.** A scan with no hit covers these bytes, these needles and these encodings: compressed or encrypted regions and a split file are not found (`evidence/coverage`).

**Does not show.** A hit shows that bytes were there, not who wrote them, what used them, or that a file existed.

**Sensitive output.** The bytes around a hit are where passwords, tokens and card numbers sit. `ioc_scan` and `chunk_needles` return none by default, and `write_values: true` (in a job run with `secret_output: true`, which the manifest sets) writes them to a sealed file you cite by file and offset, never by value. A needle is recorded in the trace: never put a secret in one. The files `feature_scan` leaves in `out_dir` are bulk_extractor's own and hold the values the evidence held (`alerts.txt` can hold a whole recovery key): the answer says `out_dir_contains_secret_values` and which kinds hold them, `out_dir` is private, and every job of the tool is secret output.
