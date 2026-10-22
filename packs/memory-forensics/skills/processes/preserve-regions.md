---
id: processes/preserve-regions
title: Preserving a process region before you rely on it
when: You will argue from a process's memory, or read a MemProcFS tree with mem_fs.
needs: []
tools: [mem_fs]
requires_host: [memprocfs, vol]
---

Use only if you will argue from a process's memory or read MemProcFS's file tree. Not for deciding what the anomaly is (`processes/injection`).

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
`secret_output: true` (`mem_fs` refuses write_values in a job that is not one; its names are shown by shape, and a UUID-shaped, hexadecimal, dotted, word-only or base32 secret in a name is printed, so a name that matters is read in such a job with `write_values`); the answer names files, never their content; `contains_secret_values` is true in a later call too when an earlier call of the job wrote values. Read
`credentials/material` before you cite anything taken from a process.

**Does not show.** A sealed copy of a region is a copy of what the capture held, not that the region was complete or that injection happened.
