---
id: processes/preserve-regions
title: Preserving a process region before relying on it
when: You will argue from a process's memory, or read a MemProcFS tree with mem_fs.
needs: []
card: mem_fs {"path": "<image>", "mount": "<dir>", "mode": "list"} first: paths vary by image and MemProcFS version. Export ({"mode": "export", "write_values": true, "paths": ["<path>"]}) in a secret_output: true job. Zero-filled ranges are unread pages. Does not show: completeness or injection.
tools: [mem_fs]
requires_host: [memprocfs, vol]
---

Use only if you will argue from a process's memory or read MemProcFS's file tree. Not for deciding what the anomaly is (`processes/injection`).

**With MemProcFS** the tree is files: processes, memory maps, handles and modules.
`mem_fs` starts `memprocfs` for one call, does one thing with the tree and stops it,
so the mount is released when the call returns and nothing later can read it, unless
the clean-up failed: the answer then names a `cleanup` problem and the mount may remain.
List first (the virtual paths depend on the image and the MemProcFS version), then
export chosen files byte for byte into `$OUT/mem_fs`:

    job_run(tool: "mem_fs", secret_output: true, args: {"path": "inputs/memory.raw",
      "mount": "{OUT}/mem", "mode": "export", "write_values": true,
      "paths": ["<a virtual path from the listing>"]})

The answer names each file and its status, never its content or digest; sizes and digests are in `export-manifest.jsonl` beside the files. Each file also
has a ranges file (`items[].ranges.file`): ranges read, unavailable, not copied and
zero-filled. With `vol` the same
questions are plugins (`triage/volatility`); record the version and the plugin
beside every result: plugin output changes between versions.

**Preserve before you rely.** Take the bytes you will argue from into a sealed job
output before calling anything injected: `mem_fs` export, or a plugin's dump, run
with `secret_output: true`, since process memory can hold secrets. Record the
image, the process (id, creation time, object address), the virtual interval, its
protection, the method (plugin and options, or virtual path and MemProcFS
version), the unavailable and zero-filled ranges (read them from the ranges file, not by
hand; zero-filled means the bytes are zeros, which MemProcFS also writes for a page it cannot
read, so not proof that data is missing), and the output
(`job:<id>/<path>`). The store holds the digest of the saved bytes. That shows what was saved, not that it was complete; cite the job
reference, and never copy a digest of a sensitive output into a post. Recovered
code is read, parsed and disassembled, never run. If extraction fails, report the
observations you have and the limitation.

**Sensitive output.** `mem_fs` export and text, and any dump, run as jobs with
`secret_output: true` (`mem_fs` refuses write_values in a job that is not one; its names are shown by shape, and a UUID-shaped, hexadecimal, dotted, word-only or base32 secret in a name is printed, so a name that matters is read in such a job with `write_values`); `contains_secret_values` is true in a later call too when an earlier call of the job wrote values. Read `credentials/material` before citing anything from a process.

**Does not show.** That a sealed copy of a region (a copy of what the capture held) is complete, or that injection happened.
