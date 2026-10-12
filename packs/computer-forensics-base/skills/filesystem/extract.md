---
id: filesystem/extract
title: Get a file out of an image, and say which record it came from
when: You need the bytes of something the listing names.
needs: [evidence/catalog]
tools: [icat_extract, catalog_search]
requires_host: [icat, fls, istat, tsk_recover]
---

Identify an extraction by the record, not by the path. State the source (the
image, and its identity from `evidence/verify`), the volume offset **in
sectors** with the sector size, the record address (an inode, and for an NTFS
stream the attribute as `168-128-4`), and the path the listing gave it. A path
is ambiguous across deleted entries and reused records, and an inode number is
reused too: the address says what that record holds in this acquisition, not
which file existed at an earlier time. On NTFS `istat` prints the record's
sequence number; record it.

Find the record with a quick look in your own shell. Every command takes the
same offset, and the same `-b <sector size>` when the sector size is not 512
(`evidence/imaging` says how to read it):

    fls -r -o <offset> image.E01 | grep -i <name>      # or catalog_search, which already ran this
    istat -o <offset> image.E01 <inode>                # size, times, allocation, attributes

The extraction itself is job work: it reads the image and writes bytes that
must be sealed and cited. Declare the image (every segment of a split set) as
inputs. A job writes only `$OUT` and the tool refuses an output outside it; `{OUT}`
in an argument stands for that directory, and a path under your own
`work/<you>/` or `work/extracted/<you>/` is rewritten to it by the harness:

    job_run tool=icat_extract args={"inode": "168-128-4", "output": "{OUT}/<name>", "image": "inputs/image.E01", "offset": <sectors>} inputs=["input:image.E01"]

`icat_extract` streams the record to the output, hashes it as it goes, and
returns the byte count, sha256, image, offset and sector size, and the path the
catalogue lists for the inode. It reads one image path: for a split raw set, run
`icat` with every segment in order as a command job. Cite the result as
`job:<id>/<path>` and record, with the inode, `istat`'s size and allocation
status and the size you received. To take a whole file system, `tsk_recover`
writes files to a directory under `$OUT`; its names come from directory entries,
not from record identity, so keep the mapping from each output name to its
record.

**What came out is not proof of what was there.** A deleted entry's clusters may
have been reused: `icat` returns whatever the record's data runs point to now.
`istat` says whether the record is allocated and which runs it lists, and
neither says the clusters still hold the file. Compare the bytes with the
record (size against the logical and initialised sizes, sparse or compressed
runs) and with the format (a header where the format has one, the structure
parsing end to end). A wrong header can mean overwritten, fragmented,
compressed, encrypted, truncated or the wrong record; a matching header is one
check, not all of them. Report the result as complete, partial, structurally
inconsistent or unidentified, and keep the bytes.

**Never run what you extract**, by any route: not an executable, and not an
interpreter, shell, browser, `import` or `eval` given the file. A no-exec mount
and stripped execute bits are partial controls, not proof that nothing can run:
`python3 x.py` runs a file whatever its mode bits say, and what a job carves
stays in its output under `store/`, which is not no-exec. Read it, parse it,
hash it; what recovered code does is established by reading it.

**Does not show.** An extracted file shows what a record's data runs held in
this acquisition. It does not show that this is the last saved version, that it
was opened, or by whom. The record's times are the file system's, in its own
resolution and zone.

**Sensitive output.** When the record is a credential store, a browser profile,
a key file, a token cache or a registry hive, run the job with
`secret_output: true`: the extracted bytes are then sealed as sensitive, and
what you record about them is where they sit, their kind and their length.
