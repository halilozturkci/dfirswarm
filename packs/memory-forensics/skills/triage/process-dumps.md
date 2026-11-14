---
id: triage/process-dumps
title: A process dump (minidump)
when: One process's dump (a file that begins with MDMP) is in the evidence.
needs: []
card: minidump_map {"path": "<dump>"}: summary first (full-memory or partial dump), then modules. An address not in the dump is unknown, not zero. A module with gaps needs {"allow_gaps": true}: state coverage_percent, never hash it against the disk file. A partial find: pass resume_va as va_start. Does not show: malice, or anything before or after the instant.
tools: [minidump_map]
requires_host: []
mentions: [cipher_state_scan]
---

Use when a file that begins with `MDMP` is in the evidence: a `.dmp` that procdump, Task Manager, WerFault or an intruder's tool wrote of one process. Not for a kernel crash dump (`PAGE`) or a full image (`triage/what-you-have`).

**Open it early.** A process dump in a disk image (Temp, Downloads, `CrashDumps`, beside a tool) is the process at one instant: its unpacked code, command line, the constants and keys it held. List every dump and its size at kickoff and read each with `minidump_map`, large ones too; no hand-written parser is needed.

**Shows.** One process at one instant: its modules, its threads with their registers, the command line its PEB held, and the memory ranges its writer chose. `view: summary` says which kind: a full-memory dump (all committed memory the writer could read) or a partial one (stacks and little else, module code mostly absent). It holds no kernel, other process, socket table or page tables, so Volatility and MemProcFS do not read it.

**Three rules.**

1. An address not in the dump is not zero but unknown: say "not in the dump" (`view: va`).
2. A module read from a dump can have gaps. `view: module` gives `coverage_percent` and each section's share; with gaps it writes only on `allow_gaps: true`, zero-fills them, names the file `.gaps` and lists them in a map file. State the coverage beside any claim on it, and do not hash it against the file on disk: it is a memory layout.
3. Search a dump for a constant or a string with `view: find` (or the ransomware pack's `cipher_state_scan` when loaded), which gives the virtual address and the file offset of each hit; then `view: read` for the bytes around one.

Order: `summary`, `modules`, then the question (`find`, `module`, `threads`, or `memory` with `protect: execute_write` and `type: private` for private executable and writable memory, a lead and not a finding; a range is listed when any region under it matches, and `matched` says which part). A `partial` from `find` gives `resume_va`: pass it as `va_start` until it is null (a dump whose streams have a fault stays `partial`), and the calls together give each hit once.

**Does not show.** That the process was malicious; what it did before or after that instant; that a string in it was used (`strings/discipline`); anything of a page the writer left out. The command line is what the process's own memory said, and a process can rewrite it. A module's timestamp is a field its author sets.

Record: the dump's hash, the header's time and flags, the dump kind, the process id, each module's base and coverage, and every hit's virtual address and file offset.
Sensitive output: `read` and `module` write memory content, so they run as a job with `secret_output: true` and `write_values: true`; cite job, path and offsets, never the content.
