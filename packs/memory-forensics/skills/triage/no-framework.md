---
id: triage/no-framework
title: A memory image no framework can read
when: The job image lacks a usable framework, symbols or dependencies; or you want an answer first.
needs: []
tools: [ioc_scan, chunk_needles, mem_carve]
requires_host: [strings, yara]
mentions: [regkv, evtx_carve, mam_scan, prefetch_mam]
---

Use when the framework, its translation layer, its symbols or a plugin dependency is missing and you must examine the bytes that can be read without it. Not for an image Volatility reads (`triage/volatility`).

When the framework, its translation layer, its symbols or a plugin dependency is
missing, examine the bytes that can be read without it, and record the specific
capability that is missing. Volatility 3 uses symbol tables in ISF form: do not call
every missing dependency a "profile". A raw-byte search stays useful, and its
conclusions are limited to the representation actually searched.

Start here, in this order:

1. **`mem_carve`** finds configured byte signatures in the file and can save a
   slice at each (`write_values: true`, in a secret job). Only if you run it: `triage/carve-signatures` says what
   each hit carries and what to record.
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

Only if the evidence includes `pagefile.sys`, swap or `hiberfil.sys`: `triage/paging-files`.

**Sensitive output.** An extracted slice can be a credential store (a SAM or
SECURITY hive, a browser database), and the bytes around a match can be a secret: run
extraction (`mem_carve` refuses it outside a secret job) and the scans as jobs with `secret_output: true`, and cite slices by job
reference and offset, never by content (`credentials/material`).

**Does not show.** That a signature hit is a whole, readable file; that a parse of a
slice describes the original structure; that a search with no hits covers other
encodings, compression or fragmented text.
