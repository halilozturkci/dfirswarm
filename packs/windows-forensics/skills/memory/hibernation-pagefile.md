---
id: memory/hibernation-pagefile
title: Hibernation files and pagefiles
when: A hiberfil.sys, pagefile.sys or swap file is the memory source.
needs: [memory/windows]
tools: [evtx_carve, mam_scan]
requires_host: [vol]
---

Use when the source is a hibernation file, pagefile or swap file. Not for a plain memory image (`memory/windows`).

- A hibernation file is a saved state. What it holds depends on how it was written (a full hibernation, or a reduced capture of the kind Fast Startup involves), and when it was written must be established from its own header and the system's power-state records. It is not automatically the machine before anyone cleaned up, and a later session can have superseded it.
- It is compressed. The byte-level tools (`evtx_carve`, `mam_scan`, strings) read stored bytes only, so a sweep of a compressed file covers what happens to be stored readable. The pack provides no decompressor: a conversion through a framework such as `vol` is a separate, recorded step that depends on that framework's support for the file, and the memory-forensics pack, if loaded, owns it.
- A pagefile or swap file holds pages that were paged out, with no addresses and no process mapping from the file itself. Scanners give strings and carved structures with file offsets only, and a structure split across pages is not whole. A hit in a pagefile is bytes in that file: not the process that held them and not the log service's memory.
- Name the file a hit came from and give its time as unknown until established.

Shows: that bytes were stored in this file at that offset. Does not show: when they were written, which process held them, or that a hibernation file predates a cleanup. Record: file, its header facts, offset, and how the time of the file was established or that it was not.

Sensitive output: a pagefile or hibernation file can hold the memory of any process; run carving over it as a job (`secret_output: true`).
