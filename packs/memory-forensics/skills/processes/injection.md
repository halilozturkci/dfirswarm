---
id: processes/injection
title: Process anomalies and candidate code modification
when: You need what was running, or are asked if code was injected into a process.
needs: []
card: Process lists, malfind regions and handles are observations, not verdicts. Identify a process by id, creation time and object address. A private executable region is a candidate (JIT and unpackers make them); a handle is a capability, not a read. mem_fs text and export: {"write_values": true}, secret_output job. Does not show: intent, that code ran, or compromise.
tools: [mem_fs]
requires_host: []
---

Use when you need what was running, or must say whether code was injected. Not for a dump.

A process tree (`triage/volatility`) gives observations to explain, not verdicts:
for each, say what memory shows, what else could produce it, and what would tell
them apart.

**Parentage that makes no sense.** `winword.exe` with a child `cmd.exe`,
`services.exe` with a child that is not a service, an `svchost.exe` whose parent is
not `services.exe`, two `lsass.exe`. Ids are reused: identify a process by id, creation
time and object address in the named layer.
Compare the linked and scanned views (`windows.pslist`, `windows.psscan`): exited
objects, reused ids, an incomplete capture and smear explain more differences than
concealment. A parent started before the child is
necessary, not sufficient.

**A path that is not the real one.** `svchost.exe` running from `C:\Users\Public`,
not `System32`, or a name one character from a system binary. Compare the full image path, the command line and any recoverable backing file; a name or a
user-space string alone is not enough.

**Memory that should not be executable.** A private executable region, a PE image
with no backing file, or a `windows.malware.malfind.Malfind` result (Linux: `linux.malware.malfind.Malfind`) is a candidate to explain. JIT
compilers, unpackers, runtime code generation and security software produce them:
"injected" is a conclusion, not a label. In Volatility 3
2.28.2 (pinned, as of October 2026) the plugin applies its own
tests and reports regions that may hold injected code, not protection alone. Injection can also use regions that are not writable at capture or change
image-backed memory, and a reflectively loaded module is not in the module list:
a clean list settles nothing. Compare mappings (`windows.vadinfo`),
backing files, module records, recoverable code and evidence of execution. State which observations
support unauthorised modification, which alternatives remain, and what would
separate them. No single protection flag or header proves injection.

**Handles and modules: what a process could reach.** Record the handle's
target, type and granted access where the engine gives them. A handle to `lsass.exe`
with read rights, or a named pipe the process did not create, shows a capability and a lead, not that anything was read,
injected or malicious (`credentials/material`).

Only if you argue from a process's memory or read MemProcFS: `processes/preserve-regions`.

**Sensitive output.** `mem_fs` export and text, and any dump, run as jobs with
`secret_output: true`; read `credentials/material` before citing anything from a process.

**Does not show.** From a process list, a region or a handle alone: intent, a
person, that code ran, that a technique was used, or that the machine was
compromised.
