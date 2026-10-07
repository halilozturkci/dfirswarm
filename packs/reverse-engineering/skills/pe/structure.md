---
id: pe/structure
title: A PE file and what its structure shows
when: The sample is a Windows-format executable, DLL or driver.
needs: [triage/quarantine]
tools: [pe_info, entropy_map, timestamp_decode]
requires_host: [r2]
---

Use when the sample is a PE (EXE, DLL, SYS, driver). Not for managed or packed code, or for what the file did: this reads structure only.

Read `status`, `problems` and `coverage` in the `pe_info` answer first. `partial` means a structure was cut, malformed, truncated by the file's end or stopped by the tool's own clock (`max_seconds`): report that, not an absence.

1. **Header time.** `header_timestamp_raw` is the COFF TimeDateStamp, a 32-bit number the linker writes, conventionally seconds counted from 1970-01-01 UTC; `header_timestamp_utc` is that reading and `timestamp_decode` renders the raw value other ways. Zero, reproducible-build and content-derived values exist (real reproducible-build DLLs read as 1982, 2043 and 2064), and a plausible one can be edited: it is not proof of compile or execution time. A value in the future, older than the APIs the file imports, or identical across unrelated samples is a lead, not a verdict; compare debug data, build records and case artefacts. A Rich header is a toolchain lead, not a clock; `pe_info` does not decode it.
2. **Sections.** Keep RVA, virtual and raw size, permissions and `entropy` (null, with `entropy_note`, when unmeasured). Size gaps, high entropy and `writable_and_executable` are triage features, not verdicts: runtimes, installers and debuggers produce them. `entropy_map` profiles the whole file, overlay included (`overlay_offset`; `overlay_is_certificate_table` true means the overlay is the signature table, not appended data).
3. **Imports** name what the loader is asked to provide, not what the code does. Networking, process-memory or crypto APIs do not show a connection, injection or encryption: read the call sites and arguments with `r2`, then corroborate elsewhere. Few imports fit packing, static linking, managed code or runtime resolution; none is concealment alone.
4. **Directories.** `declares_clr_runtime_header` means managed code: this pack has no .NET metadata reader, so say that before saying what the application can do. `declares_tls` (callbacks can run before the entry point), `declares_delay_imports` and `declares_resources` name structures `pe_info` does not read.
5. A locator carries its type: file offset, RVA or VA. The entry point is an RVA.

Only if you need exports, the certificate or resources, read `pe/signature-and-resources`.

Shows: header fields as written, section layout, declared imports, which directories exist. Does not show: compile time, packing, intent, signature validity, resources. Record: `pe_info` status and problems, raw and rendered timestamp, offsets with their type, what was not read.
