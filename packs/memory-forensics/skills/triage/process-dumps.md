---
id: triage/process-dumps
title: A process dump (minidump)
when: One process's dump (a file that begins with MDMP) is in the evidence.
needs: []
tools: [minidump_map]
requires_host: []
mentions: [cipher_state_scan]
---

Use when a file that begins with `MDMP` is in the evidence: a `.dmp` that procdump, Task Manager, WerFault or an intruder's own tool wrote of one process. Not for a kernel crash dump (`PAGE`) or a full image (`triage/what-you-have`).

**Open it early.** A process dump found in a logical disk image (a user's Temp or Downloads, `CrashDumps`, beside a tool) is the process at one instant: its unpacked code, its command line, the constants and keys it held. List every dump with its size at the kickoff and read each with `minidump_map`; a large one is not a reason to leave it, and no hand-written parser is needed.

**Shows.** One process at one instant: its modules, its threads with their registers, the command line its PEB held, and the memory ranges its writer chose. `view: summary` says which kind: a full-memory dump (all committed memory the writer could read) or a partial one (stacks and little else, module code mostly absent). It holds no kernel, no other process, no socket table and no page tables, so Volatility and MemProcFS do not read it and their plugins do not apply.

**Three rules.**

1. An address that is not in the dump is not zero. Its content is unknown; say "not in the dump" (`view: va`).
2. A module read from a dump can have gaps. `view: module` gives `coverage_percent` and each section's share; with gaps it writes only on `allow_gaps: true`, zero-fills them, names the file `.gaps` and lists them in a map file. State the coverage beside any claim built on that image, and do not hash it against the file on disk: it is a memory layout.
3. Search a dump for a constant or a string with `view: find` (or with the ransomware pack's `cipher_state_scan` when that tool is loaded), which gives the virtual address and the file offset of each hit; then `view: read` for the bytes around one.

Order: `summary`, `modules`, then the question (`find`, `module`, `threads`, or `memory` with `protect: execute_write` and `type: private` for memory that is executable and writable in no module, a lead and not a finding).

**Does not show.** That the process was malicious; what it did before or after the instant of the dump; that a string in it was used (`strings/discipline`); anything of a page the writer left out. The command line is what the process's own memory said, and a process can rewrite it. A module's timestamp is a field its author sets.

Record: the dump's hash, the header's time and flags, the kind of dump, the process id, each module's base and coverage, and the virtual address and file offset of every hit.
Sensitive output: `read` and `module` write memory content, so they run as a job with `secret_output: true` and `write_values: true`; cite the job, the path and the offsets, never the content.
