---
id: processes/injection
title: Process anomalies and candidate code modification
when: You need what was running, or you are asked whether code was injected into a process.
needs: [triage/what-you-have, triage/volatility]
tools: [mem_fs]
requires_host: [memprocfs, vol]
---

With a framework the process tree is one command. What it shows is a set of
observations to explain, not verdicts. For each, say what the memory shows, what
else could produce it, and what would tell them apart.

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

**With MemProcFS** the tree is files: processes, memory maps, handles and modules.
`mem_fs` starts `memprocfs` for one call, does one thing with the tree and stops it,
so the mount is gone when the call returns and nothing later can read it. Use its
list mode to see the virtual paths the image and the MemProcFS version actually
expose, and its export mode to copy chosen files byte for byte into the job's
`$OUT/mem_fs`:

    job_run(tool: "mem_fs", secret_output: true, args: {"path": "inputs/memory.raw",
      "mount": "{OUT}/mem", "mode": "export", "write_values": true,
      "paths": ["<a virtual path from the listing>"]})

The answer names each file and its status, never its content or digest; the sizes
and digests are in `export-manifest.jsonl` beside the files. With Volatility
(`vol`) the same questions are plugins (`triage/volatility`, which also gives the
dump option of each OS); record the version and the plugin name beside every
result, since plugin output changes between versions.

**Preserve before you rely.** Take the bytes you will argue from into a sealed job
output before you call anything injected: `mem_fs` export, or a plugin's dump, run
with `secret_output: true`, because a process's memory can hold secrets. Record the
image, the process (id, creation time, object address), the virtual interval, its
protection, the method (plugin and options, or virtual path and MemProcFS
version), any pages that were unavailable or zero-filled, and the output
(`job:<id>/<path>`). The store holds the digest of the saved bytes. That shows what
was saved, not that the region was complete or that injection happened; cite the job
reference, and do not copy a digest of a sensitive output into a post. Recovered
code is read, parsed and disassembled, never run. If the extraction fails, report
the observations you do have and the limitation.

**Sensitive output.** `mem_fs` export and text, and any dump, run as jobs with
`secret_output: true`; the answer names files, never their content. Read
`credentials/material` before you cite anything taken from a process.

**Does not show.** From a process list, a region or a handle alone: intent, a
person, that code ran, that a technique was used, or that the machine was
compromised. A sealed copy of a region is a copy of what the capture held.
