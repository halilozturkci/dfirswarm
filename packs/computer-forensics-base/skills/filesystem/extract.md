---
id: filesystem/extract
title: Get a file out of an image and name its record
when: You need the bytes of something the listing names.
needs: []
tools: [icat_extract, catalog_search, byte_range_extract]
requires_host: [icat, fls, istat, tsk_recover]
---

Use when the listing names something whose bytes you need. Not for what a path, an inode or an allocation flag means (`filesystem/semantics`) or for bytes with no record (`filesystem/carving`).

Identify an extraction by the record, not the path. State the image and its identity (`evidence/verify`), the volume offset **in sectors** with the sector size, the record address (an inode; for an NTFS stream the attribute, `168-128-4`) and the listed path. On NTFS record the sequence number `istat` prints.

Find the record in your shell. Every command takes the same offset, and the same `-b <sector size>` when it is not 512 (`evidence/imaging`):

    fls -r -o <offset> image.E01 | grep -i <name>      # or catalog_search, which already ran this
    istat -o <offset> image.E01 <inode>                # size, times, allocation, attributes

The extraction itself is job work: it reads the image and writes bytes that must be sealed and cited. Declare the image (every segment of a split set) as inputs. A job writes only `$OUT` (`{OUT}`); a path under your `work/<you>/` or `work/extracted/<you>/` is rewritten to it:

    job_run tool=icat_extract args={"inode": "168-128-4", "output": "{OUT}/<name>", "image": "inputs/image.E01", "offset": <sectors>} inputs=["input:image.E01"]

`icat_extract` streams the record to the output, hashes it, and returns the byte count, sha256, image, offset, sector size and the catalogue's path for the inode. It reads one image path, or a layer descriptor (`descriptor`), which is how it reads a split raw set. Cite the result as `job:<id>/<path>` and record `istat`'s size and allocation status and the size received. `tsk_recover` writes a whole file system's files under `$OUT`, named from directory entries, not record identity: keep each name's record.

**What came out is not proof of what was there.** `icat` returns whatever the record's data runs point to now, and a deleted entry's clusters may be reused. Compare the bytes with the record and the format; report complete, partial, structurally inconsistent or unidentified (`filesystem/semantics`). Keep the bytes. A database comes out with its files beside it (`data/sqlite`). `byte_range_extract` copies declared byte ranges, hashing those of 128 bytes or more; a byte range is not a file.

**Never run what you extract**, by any route: not an executable, and not an interpreter, shell, browser, `import` or `eval` given the file. Stripped execute bits and a no-exec mount are partial controls: `python3 x.py` runs a file whatever its mode, and carves under `store/` are not no-exec. Read it, parse it, hash it; what recovered code does is established by reading it.

**Does not show.** An extracted file shows what a record's data runs held in this acquisition, not that it is the last saved version, was opened, or by whom. The record's times are the file system's.

**Sensitive output.** When the record is a credential store, a browser profile, a key file, a token cache or a registry hive, run the job with `secret_output: true`: the bytes are sealed, and you record where they sit, their kind and their length.
