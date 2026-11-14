---
id: triage/volatility-symbols
title: The image's symbol tables, and a missing one
when: The error names a PDB, GUID and age, or you say which kernels the image reads.
needs: []
card: A Windows table is matched by PDB name, GUID and age: search vol -q isfinfo for the GUID; a listing without it covers only the directories this vol searched. Tell a missing table from a stale cache, a missing layer, an unsupported format or a missing plugin dependency. Close the lead needs_operator with the PDB, GUID, age and what you checked. isf_intake {"path": "<image>", "debug": "<vmlinux>", "kind": "elf"} makes Linux tables only. Tables stay local-only. Does not show: that one table covers a Windows release.
tools: [isf_intake]
requires_host: [vol]
---

Use only if Volatility reports a missing or invalid symbol table, or you must say which kernels the image can read. Not for choosing plugins (`triage/volatility-plugins`).

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

**When the table is not there.** Distinguish a missing or invalid
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

**Does not show.** That a table's presence in a listing covers the whole kernel family or a Windows release; that a listing without the GUID means the kernel cannot be read anywhere; that a supplied table is valid before it was validated.

Sensitive output: none here; a symbol table is not a secret, but it stays local-only and never goes into a job's output or a thread (one exception: the Linux table `isf_intake` writes, `symbols/linux`).
