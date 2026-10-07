---
id: triage/volatility
title: Volatility with the right symbols, offline
when: You are selecting Volatility plugins, validating Windows, Linux or macOS symbols, or diagnosing an unsatisfied symbol or translation requirement.
needs: [triage/what-you-have, credentials/material]
tools: [mem_profile]
requires_host: [vol]
---

Run Volatility offline first, as a job (`job_run`), so its stdout and stderr stay
whole in the job. A result that needed an unrecorded symbol download is not
reproducible on an isolated examiner workstation. Run `mem_profile` first, so that
the container and the captured ranges are what you think they are.

    vol --offline -vv -f IMAGE windows.info

A plugin that writes files takes `-o "$OUT"`. Record the `Volatility 3 Framework`
version line, the plugin, the image hash and the symbol identity: the kernel is
named by its PDB name, GUID and age (`ntkrnlmp.pdb`, 32 hexadecimal digits, a
number). With `-vv` the `Symbols` row of `windows.info` names the table Volatility
read (`windows/<pdb>/<GUID>-<age>.json.xz`), and without a table its log names the
symbol-server address it would have fetched, which carries the same identity. Keep
the selected table's URI and provenance, not only the identity you asked for.

**What the image holds.** `/etc/dfirswarm/tools.md`, under "Data the programs
read", names the data the image carries (a host run has no image, and holds no
table unless the operator put one under `volatility3/symbols`): the exact tables
the operator's build made for the kernels its pack lists (`grep <GUID>
/etc/dfirswarm/tools.md`), and the Volatility Foundation's bundle of 2019, which
covers the Windows builds of 2019 and earlier, so a newer kernel is usually not in
it. The curated list is a set of exact kernels, not a coverage claim for any
Windows release (Windows 11 and the Server releases included); the GUID is the
check. In Volatility 3 2.28.2 (as of October 2026) `vol -q isfinfo` lists every
table the cache knows, and its `--filter` applies only with `--live`, which opens
every table: search the listing for the GUID (`vol -q isfinfo | grep -i <GUID>`).
A listing without it covers the symbol directories this `vol` searched; it is a
bounded result. An image built without its symbol sets says so in the same file
("left out by the build").

**If the error names a PDB, GUID and age**, the tables this `vol` could see do not
include it. Do not switch off `--offline`, and fetch nothing. Never copy a symbol
table into a job's output, a thread or the sandbox: it would travel with the report
package, and the build's tables are local-only. Distinguish a missing or invalid
table from a stale or inaccessible cache, a missing translation layer, an
unsupported format and a missing plugin dependency before you report which it was.
Close the lead `needs_operator` with the PDB, the GUID, the age and what you
checked: the operator adds the kernel to the pack's curated list, fetches its PDB on
the host (`swarm.sh symbols fetch`) and rebuilds the image, or makes the table and
supplies it to the run (`tool-supply`), and you point Volatility at a supplied
directory with `-s DIR`. For a supplied table record its source, the converter and
its version, the table's identity and digest, the URI Volatility selected, the
validation result and any duplicate identity. Say in the report which plugins that
need the symbol were not run, and which checks that need no kernel symbols
(strings, YARA, carving: `triage/no-framework`) were.

**The kickoff's catalogue.** When it is on, the base pack's `memory-windows` recipe
has run `windows.info` and a baseline of plugins: read its receipts, and
`catalog/missing.json`, which names the kernel when the image lacks its table. Its
detection is a bounded Windows probe, not a check of every platform or plugin. The
recipe is being changed in the base pack's own change: its run path currently
retries without `--offline` when the image lacks the table, which only a job whose
network allows it can reach, and its coverage then says the symbols were fetched.
This skill's rule stands either way: you do not run that fallback. Inspect the
executed command and the coverage text before you describe any recipe output as
offline, and say when it was not.

**Windows.** Establish the kernel once with `windows.info`, then compare views:

    windows.pslist     linked process list
    windows.psscan     pool scan, including exited or unlinked remnants
    windows.pstree     parentage, to check against creation times
    windows.cmdline    command lines where resident
    windows.netstat    network structures the kernel's tracking lists reach
    windows.netscan    a scan for network objects (see network/state)
    windows.malware.malfind.Malfind   candidate private executable regions
    windows.vadinfo    the region boundaries and protections behind a candidate
    windows.handles    what a process could reach
    windows.modules / windows.dlllist   kernel and per-process modules
    windows.svcscan    registered and residual services

As of October 2026, in 2.28.2, the older `windows.malfind` and `linux.malfind`
names are deprecated forwarding classes of the `.malware.malfind` plugins (a
receipt that names the old one ran the alias); the plugin lists a candidate, not
proof of injection, and its Windows option for writing the regions it finds is
`--dump`. Verify the options of a plugin in the image you have (`vol
windows.malware.malfind.Malfind --help`, and `vol --help` for the plugin list it
carries): plugin output and options change between versions.

**Linux.** There is no exhaustive public cache: the ISF must match the exact
kernel build, with its architecture, and a nearby distribution version is not a
substitute. Establish the kernel banner and a matching ISF before any
symbol-dependent analysis; as of October 2026, in 2.28.2, the plugins include
`linux.pslist.PsList`, `linux.pstree.PsTree`, `linux.lsof.Lsof`,
`linux.sockstat.Sockstat`, `linux.envars.Envars`, `linux.bash.Bash` and
`linux.malware.malfind.Malfind`, whose option for writing regions is
`--dump-regions` (not the Windows `--dump`; it has its own `--dump-maxsize`, 1 GB
by default). This pack supplies no Linux or macOS ISF set and no converter:
require an ISF made from matching kernel debug material that the case or the
operator supplies, record its provenance, and validate the captured kernel's
identity and architecture. Where the matching table is absent, symbol-dependent
Linux analysis was not performed, and the report says so. A plugin being listed
does not show that the captured kernel is supported. For macOS this pack makes no
support claim for any version: the same rule applies, and an unsupported target is
reported as unexamined.

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
