---
id: triage/no-framework
title: What a memory image gives you when no framework can read it
when: The selected job image lacks a usable framework, its symbols or dependencies, or does not support the capture; or you want an answer before you configure one.
needs: [triage/what-you-have, credentials/material]
tools: [mem_carve, ioc_scan, sig_carve, chunk_needles]
requires_host: [strings, yara]
mentions: [regkv, evtx_carve, mam_scan, prefetch_mam]
---

When the framework, its translation layer, its symbols or a plugin dependency is
missing, examine the bytes that can be read without it, and record the specific
capability that is missing. Volatility 3 uses symbol tables in ISF form: do not call
every missing dependency a "profile". A raw-byte search stays useful, and its
conclusions are limited to the representation actually searched.

Start here, in this order:

1. **`mem_carve`** finds configured byte signatures in the file and can save a
   fixed-size slice at each: registry hives (`regf`), event log chunks and files,
   Prefetch records (plain `SCCA`, and compressed `MAM\x04`), PE headers, SQLite
   databases, MFT and index records, zip, PDF and property lists. It does not
   rebuild a fragmented file, decompress hibernation data or parse paging structures.
   Each hit has a `signature_offset`, an `object_offset` where the structure starts
   (a plain Prefetch record starts four bytes before `SCCA`; null when that is not
   established) and a `validation` (header plausible, implausible, truncated or only
   a signature). Offsets are offsets in the file, and the offsets are the whole
   provenance: there is no path. Record the signatures selected, the interval
   searched, the hit count, the extraction limit (default 25, earliest hits first)
   and how many hits were not extracted. A slice can start inside a structure, end
   before it finishes or run into unrelated adjacent pages: check its start, its
   declared length and its internal consistency before you choose a parser, and
   treat a successful parse as evidence about the records it validated.
   `sig_carve` reports a signature the same way: for a plain Prefetch record, where
   `SCCA` is, not where the structure begins.
2. **Hand each slice to its own parser, if the pack that has it is loaded.** The
   Windows Forensics pack's `regkv` reads a hive, `evtx_carve` an event log chunk,
   `mam_scan` and `prefetch_mam` a Prefetch record (a plain one must begin at its
   version field, which is what `object_offset` gives). They are not in this pack's
   dependencies: check the run's tool inventory first. If the parser is absent,
   keep the candidate with its offsets, say the downstream parse was not done, and
   do not claim one. This is the step first passes skip, and it is where answers
   are.
3. **`ioc_scan` and `chunk_needles`** for an address, a path, a domain or a name in
   ASCII and UTF-16LE with offsets and context, and `strings -a -t d -e l IMAGE` for
   a first look at wide text. `strings/discipline` says how to report what they find.
4. **YARA only with a rule you can defend.** Fetch `patterns/yara` before a
   whole-image scan with `yara`. Keep every match with its rule, string identifier
   and offset; a match with no process or region attribution is a lead, not behaviour.

What this cannot give you: a process list, a parent-child tree, handle tables, or
anything that needs the page tables walked. Do not approximate those by pattern
matching and present the result as a process list: say that no framework was
available, and name what you did instead.

**The page file and the hibernation file are memory too, and different.** Inventory
`pagefile.sys`, swap and `hiberfil.sys` separately, with their collection times and
the system they came from. Literal scanning finds bytes stored directly in a paging
file; it cannot assign them to a process, a virtual address or a time. A hibernation
file may need a supported decoder before its saved memory can be searched. Record the
areas that were unsupported, compressed, encrypted, missing or not processed, and
remember that what these hold can describe a different time from the RAM capture.

**Sensitive output.** An extracted slice can be a credential store (a SAM or
SECURITY hive, a browser database), and the bytes around a match can be a secret: run
extraction and the scans as jobs with `secret_output: true`, and cite slices by job
reference and offset, never by content (`credentials/material`).

**Does not show.** That a signature hit is a whole, readable file; that a parse of a
slice describes the original structure; that a search with no hits covers other
encodings, compression or fragmented text.
