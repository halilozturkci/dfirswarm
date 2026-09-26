---
id: normalise/layout
title: The paths in the tree are not the paths on the machine
when: Before you cite anything by path.
needs: [identify/collector]
tools: [collection_index]
requires_host: []
---

Every collector rewrites paths to be safe on the examiner's file system, and
each does it differently. Citing the path you see, without the mapping, cites
something that never existed.

What gets rewritten, and why it matters:

- **The drive letter or root.** `C:\Windows` becomes `C/Windows`, or
  `%FileSystem%/Windows`, or a directory named after the volume's serial.
- **A colon in a named stream.** `file.txt:payload` cannot exist on most file
  systems, so it becomes `file.txt_payload`, or `file.txt.payload`, or the
  stream is dropped entirely. **A dropped stream is a silent loss**, and it is
  exactly what a Windows case may turn on: see `filesystem/ads` in the Windows
  pack.
- **Reserved names.** `LPT1.txt` and `COM1` cannot be created on Windows and are
  renamed by a Windows-based collector.
- **Long paths and unicode.** Truncated, or transliterated.
- **Case.** A case-insensitive source collected onto a case-sensitive file
  system, or the reverse, can collide two files into one.

`collection_index` builds the index the rest of the work needs: every file with
its size, its hash, the path it has now and a cautiously reconstructed source
path. The reconstruction is a convention-based hypothesis; confirm it against
the collector's manifest. The tool refuses a directory containing a disk image,
because the E01 name is a container path, not a source-machine path.

**Cite both.** "`C:\Users\alice\NTUSER.DAT` (in the collection at
`C/Users/alice/NTUSER.DAT`, sha256 …)" is a citation somebody else can follow
in either direction. One without the other is not.

Once the index exists, the platform packs work unchanged: a hive is a hive, an
`.evtx` is an `.evtx`, and `$MFT` copied off a live volume parses exactly as it
would from an image.
