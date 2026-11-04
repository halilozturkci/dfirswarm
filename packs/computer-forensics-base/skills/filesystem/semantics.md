---
id: filesystem/semantics
title: Filesystem identity, allocation and recovery limits
when: Citing a file by path or inode, reading a deleted entry, or saying it was deleted.
needs: []
tools: [icat_extract]
requires_host: [istat]
---

Use when a path, an inode, a size, an allocation flag or a recovered file becomes a statement. Not for the volume offset (`evidence/imaging`), carving (`filesystem/carving`) or the extraction steps (`filesystem/extract`).

**Identity.**
- A path is a name an entry carried at acquisition. It can be one of several (hard links; NTFS's short and long names), can be reused by a later file, and can belong to a deleted entry.
- The object is the record (an inode or MFT record) and, for a named stream or fork (separate data under the file's name, `name:stream` on NTFS), the attribute. A record number is reused after deletion: record its sequence or generation number where there is one (`istat` prints NTFS's); the address names what the record holds in this acquisition, not which file existed earlier.

**Size.** Logical size (what the file claims), allocated size (clusters held) and, on NTFS, initialised size are three numbers; a sparse or compressed file stores less than it claims. Record which `istat` gave and the count `icat_extract` returned; explain a difference.

**Allocation and deletion.**
- An allocated flag is the state at acquisition, not at an earlier time.
- A deleted record's data runs point to clusters that may be free or reused. `icat_extract` returns what they hold now, which can be another file. A wrong header can mean overwritten, fragmented, compressed, encrypted, truncated or the wrong record; a matching header or size is one check, not all of them; a structure that parses end to end is stronger.
- State the result as complete, partial, structurally inconsistent or unidentified; keep the bytes. "Cannot be recovered" is written only after naming the routes tried: the record, the journal, snapshots, backups, carving.
- Slack (bytes after a file's end in its last cluster), unallocated space and the journals are different sources: search each on purpose or name it skipped.

**Times.** A file system's times are its own: set by creation, copy, move, extraction, restore and backup, held at its resolution and zone, and sometimes not updated (last access: find out whether this volume did). They do not show who acted (`timeline/clocks`).

**Other states.** A snapshot or shadow copy is a past state of the volume and a separate source (`filesystem/layers`). A flash device may discard freed blocks itself (TRIM, garbage collection): content gone from an SSD does not show a person erased it. A logical collection may never have held slack or unallocated space (`evidence/collections`).

**Record.** The image and its identity, the volume offset in sectors and the sector size, the record address, the listed path, `istat`'s size and allocation status, the size received, the sha256 and your check of the content.

**Shows.** What a record's data runs held in this acquisition. **Does not show.** That this is the last saved version, that it was opened, or by whom; nor that a file never existed because no record names it.

**Sensitive output.** When the record is a credential store, a key file or a browser profile, run the extraction with `secret_output: true` and record where it sits, its kind and length.
