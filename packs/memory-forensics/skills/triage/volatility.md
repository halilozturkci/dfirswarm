---
id: triage/volatility
title: Volatility, offline, with the right symbols
when: Selecting Volatility plugins, or diagnosing an unmet symbol or translation requirement.
needs: []
card: mem_profile first; vol_views {"path": "<image>", "question": "<plugin as vol lists it>", "readiness": "<vol_readiness answer file>"} runs one listed plugin offline, on a ready answer only. An error naming a PDB, GUID and age: keep --offline, fetch nothing. Raw output: {"write_values": true}, secret_output job. Empty output is an absence only after a complete run with the right table. Does not show: that every plugin works.
tools: [mem_profile, vol_readiness, vol_views, isf_intake]
requires_host: [vol]
---

Use when you run Volatility against a memory image. Not for an image no framework can read (`triage/no-framework`).

Run Volatility offline first, as a job (`job_run`), so stdout and stderr stay whole: a
result that needed an unrecorded symbol download is not reproducible offline. Run
`mem_profile` first to confirm the container and the captured ranges.

    vol --offline -vv -f IMAGE windows.info

`vol_readiness` asks first, offline, with no plugin result: whether `vol` is there, which plugins it lists, whether the image's kernel has a table (`ready`, `blocked` or `unknown`), whether a YARA binding imports, whether FUSE is usable. `vol_views` then runs one plugin the installed `vol` lists, offline, on that `ready` answer, and keeps its whole output (raw output only in a job with `secret_output: true`).

A plugin that writes files takes `-o "$OUT"`. Record the `Volatility 3 Framework`
version line, the plugin, the image hash and the symbol identity: the kernel is
named by its PDB name, GUID and age (`ntkrnlmp.pdb`, 32 hexadecimal digits, a
number). With `-vv` the `Symbols` row of `windows.info` names the table Volatility
read (`windows/<pdb>/<GUID>-<age>.json.xz`), and without a table its log names the
symbol-server address it would have fetched, which carries the same identity. Keep the selected table's URI and provenance too.

**If the error names a PDB, GUID and age**, no table this `vol` could see
has it. Do not switch off `--offline`, and fetch nothing. Never copy a symbol
table into a job's output, a thread or the sandbox: it would travel with the report package, and tables are local-only (the one
exception, `isf_intake`'s table, leaves $OUT before any report: `symbols/linux`).

Only if a table is missing or invalid, or to know what the image carries: `triage/volatility-symbols`. Only if you pick an OS's plugins or the option that writes regions: `triage/volatility-plugins`. Only if the kickoff's catalogue has run: `triage/volatility-catalogue`.

**Sensitive output.** Plugins that print command lines, environment blocks, shell
history or memory content (`windows.cmdline`, `linux.envars`, `linux.bash`, any dump) can expose
credentials: run them, and any region extraction, as jobs with `secret_output: true`,
and report what they show without copying a secret (`credentials/material`).

**Does not show.** That `windows.info` working means every other plugin works on
the build; that an empty plugin result means nothing was there. Empty output is an
absence only after the plugin completed with the matching symbol table, the right
input, its filters and any process or region it skipped or could not read stated;
record each plugin's scope and limits.
