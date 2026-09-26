---
id: triage/no-framework
title: What a memory image gives you with no framework at all
when: The host has no Volatility and no MemProcFS, or you want an answer before you configure one.
needs: [triage/what-you-have]
tools: [mem_carve, ioc_scan, sig_carve, chunk_needles]
requires_host: [strings, yara]
---

A framework needs a symbol profile that matches the build. Getting one can take
longer than the question deserves, and on an unusual build it may not exist.
Meanwhile the image is a large blob with recognisable structures in it, and the
base pack's carving tools read blobs.

Start here, in this order:

1. **`mem_carve`** sweeps for the structures that carry time and identity:
   registry hives (`regf`), event log chunks (`ElfChnk`), prefetch records
   (`MAM\x04`), PE headers, SQLite databases, and the Windows page-file
   structures. Each hit comes back with its offset, and the offset is the whole
   provenance: there is no path.
2. **Hand each carved structure to its own parser.** A hive carved out of memory
   is read by `regkv` exactly as one extracted from a disk would be; a chunk
   goes to `evtx_carve`; a prefetch record to `mam_scan`. This is the part first
   passes skip, and it is where the answers are.
3. **`ioc_scan` and `chunk_needles`** for an address, a path, a domain or a name
   in ASCII and UTF-16LE, with offsets and context.
4. **YARA only with a rule you can defend.** Fetch `patterns/yara` before a
   whole-image scan. Keep every match with its rule, string identifier and
   offset; a match with no process/region attribution is a lead, not behaviour.

What this cannot give you: a process list, a parent-child tree, handle tables,
or anything that needs the page tables walked. Do not approximate those by
pattern matching and present the result as a process list — say that no
framework was available and name what you did instead.

**Do not forget the page file and the hibernation file**, which are memory too.
`pagefile.sys` holds pages the kernel evicted, including decrypted buffers and
command lines, and it is a flat blob that all of the above read directly.
