---
id: triage/volatility
title: Volatility, offline, with the right symbols
when: Selecting Volatility plugins, or diagnosing an unmet symbol or translation requirement.
needs: []
tools: [mem_profile, vol_readiness, vol_views, isf_intake]
requires_host: [vol]
---

Use when you run Volatility against a memory image. Not for an image no framework can read (`triage/no-framework`).

Run Volatility offline first, as a job (`job_run`), so its stdout and stderr stay
whole in the job. A result that needed an unrecorded symbol download is not
reproducible on an isolated examiner workstation. Run `mem_profile` first, so that
the container and the captured ranges are what you think they are.

    vol --offline -vv -f IMAGE windows.info

`vol_readiness` asks first, offline and without a plugin result: whether `vol` is there, which plugins it lists, whether the image's kernel has a table (`ready`, `blocked` or `unknown`), whether a YARA binding imports and whether FUSE is usable. `vol_views` then runs one plugin the installed `vol` lists, offline, on that `ready` answer, and keeps its whole output (the raw output only in a job run with `secret_output: true`).

A plugin that writes files takes `-o "$OUT"`. Record the `Volatility 3 Framework`
version line, the plugin, the image hash and the symbol identity: the kernel is
named by its PDB name, GUID and age (`ntkrnlmp.pdb`, 32 hexadecimal digits, a
number). With `-vv` the `Symbols` row of `windows.info` names the table Volatility
read (`windows/<pdb>/<GUID>-<age>.json.xz`), and without a table its log names the
symbol-server address it would have fetched, which carries the same identity. Keep
the selected table's URI and provenance, not only the identity you asked for.

**If the error names a PDB, GUID and age**, the tables this `vol` could see do not
include it. Do not switch off `--offline`, and fetch nothing. Never copy a symbol
table into a job's output, a thread or the sandbox: it would travel with the report
package, and the build's tables are local-only (the one table `isf_intake` writes into $OUT is removed from it before any report: `symbols/linux`).

Only if a table is missing or invalid, or you need to know what the image carries: `triage/volatility-symbols`. Only if you pick plugins for an operating system or the option that writes regions: `triage/volatility-plugins`. Only if the kickoff's catalogue has run: `triage/volatility-catalogue`.

**Sensitive output.** Plugins that print command lines, environment blocks, shell
history or memory content (`windows.cmdline`, `linux.envars`, `linux.bash`, and any
plugin that dumps) can expose credentials: run them, and any region extraction, as
jobs with `secret_output: true`, keep the whole output in the sealed job, and report
what they show without copying a secret value. `credentials/material` says how.

**Does not show.** That `windows.info` working means every other plugin works on
the build; that an empty plugin result means nothing was there. Empty output is an
absence only after the plugin completed with the matching symbol table, the right
input, its filters and any process or region it skipped or could not read stated;
record each plugin's scope and limits separately. Keep stdout and stderr whole.
