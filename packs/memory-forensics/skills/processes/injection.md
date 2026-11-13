---
id: processes/injection
title: Process anomalies and candidate code modification
when: You need what was running, or are asked if code was injected into a process.
needs: []
tools: [mem_fs]
requires_host: []
---

Use when you need what was running, or must say whether code was injected. Not for a dump.

With a framework the process tree is one command (`triage/volatility`). What it
shows is a set of observations to explain, not verdicts. For each, say what the
memory shows, what else could produce it, and what would tell them apart.

**Parentage that makes no sense.** `winword.exe` with a child `cmd.exe`,
`services.exe` with a child that is not a service, an `svchost.exe` whose parent is
not `services.exe`, two `lsass.exe`. A process id is reused, so identify a process
by its id together with its creation time and its object address in the named layer.
Compare the linked and the scanned views (`windows.pslist` against
`windows.psscan`): exited objects, a reused id, an incomplete capture and smear
explain more differences than concealment does. A parent whose start time is
earlier than the child's is necessary, not sufficient.

**A path that is not the real one.** `svchost.exe` running from `C:\Users\Public`
rather than `System32`, or a name one character from a system binary. Compare the
full image path, the command line and any recoverable backing file; a name or a
user-space string alone is not enough.

**Memory that should not be executable.** A private executable region, a PE image
with no backing file, or a `windows.malware.malfind.Malfind` result (on Linux
`linux.malware.malfind.Malfind`) is a candidate that needs an explanation. Just-in-time
compilers, unpackers, runtime code generation and security software produce them,
so "injected" is a conclusion to reach, not a label for the result. In Volatility 3
2.28.2 (as of October 2026, the version this pack pins) the plugin applies its own
tests and describes its output as regions that potentially hold injected code; it
does not report on protection alone. Injection can also use regions that are not
writable at capture or change image-backed memory, and a reflectively loaded module
has no entry in the module list, so a clean list does not settle the question
either. Compare the mappings (`windows.vadinfo`), the backing files, the module
records, the recoverable code and evidence of execution. State which observations
support unauthorised modification, which alternatives remain, and what would
separate them. No single protection flag or header proves injection.

**Handles and modules describe what a process could reach.** Record the handle's
target, type and granted access where the engine gives them. A handle to `lsass.exe`
with read rights, or a named pipe the process did not create, shows a capability
and a lead; it does not show that anything was read, injected or malicious
(`credentials/material` separates the stages).

Only if you argue from a process's memory or read MemProcFS: `processes/preserve-regions`.

**Sensitive output.** `mem_fs` export and text, and any dump, run as jobs with
`secret_output: true` (`credentials/material` before you cite anything taken from a process).

**Does not show.** From a process list, a region or a handle alone: intent, a
person, that code ran, that a technique was used, or that the machine was
compromised.
