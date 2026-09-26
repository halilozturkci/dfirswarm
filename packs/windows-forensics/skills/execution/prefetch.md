---
id: execution/prefetch
title: Prefetch, and the compressed format
when: You need a run count, a last run time, or what a binary loaded.
needs: [execution/overview]
tools: [prefetch_mam, mam_scan]
requires_host: [icat]
---

`C:\Windows\Prefetch\<NAME>.EXE-<HASH>.pf`. The hash is derived from the
executable path (with format- and hosted-application-specific inputs), so the
same binary in two directories normally makes two files, and a renamed binary
makes a new one. Do not describe it as a hash of the file bytes.

From Windows 8 onwards the file is compressed, with a `MAM\x04` header and an
LZXPRESS Huffman body. `prefetch_mam` decompresses it and returns the executable
name, format version, prefetch hash, run count, last-run times (up to eight on
modern builds), and all recoverable UTF-16 strings and paths. Confirm volume
information with a second parser such as `sccainfo`. Do not try to read it with a plain parser:
it will return nothing and you will conclude the file is empty.

What it gives you, in order of usefulness: the last run time to the second, the
run count, the list of files and directories the process touched during its
first ten seconds, and the volume serial.

The loaded-file list is the part people skip and it is often the answer. A
downloader shows `WININET`, `URLMON`, `WINHTTP`, `WS2_32`. A binary that touched
`C:\Windows\Prefetch` and nothing else is deleting prefetch files.

In unallocated space the records survive without the file. `mam_scan` sweeps a
raw dump for `MAM\x04`, decompresses each hit and returns the same fields with
the offset it came from. That is how execution was proved in the published case
where the only evidence was unallocated space.

Where the host has `sccainfo` or `PECmd`, run one of them over the same file and
compare the run count and the last run time. They are the two figures most often
quoted from prefetch and the two most worth having twice.

Two zero-length files in the prefetch directory with named streams on them mean
a binary was launched from a stream. See `filesystem/ads`.
