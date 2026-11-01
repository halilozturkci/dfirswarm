---
id: triage/volatility-plugins
title: Volatility plugins by operating system
when: Choosing Windows, Linux or macOS plugins, or the option that writes a region to disk.
needs: []
tools: [mem_registry, isf_intake]
requires_host: [vol]
---

Use only if you pick plugins for a Windows, Linux or macOS image. Not for the offline rule or symbols (`triage/volatility`).

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

`mem_registry` lists the hives and reads one key of one hive through `vol`, offline; it withholds credential-named values and refuses SAM and SECURITY outside a secret-output job.

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
by default). This pack supplies no Linux or macOS ISF set; `isf_intake` converts
the Linux debug material the operator supplies and is ready only on an exact
banner match. Record the provenance, and validate the kernel's identity and
architecture. Where the matching table is absent, symbol-dependent
Linux analysis was not performed, and the report says so. A plugin being listed
does not show that the captured kernel is supported. For macOS this pack makes no
support claim for any version: the same rule applies, and an unsupported target is
reported as unexamined.

**Sensitive output.** `windows.cmdline`, `linux.envars`, `linux.bash` and every plugin that dumps a region can expose credentials: jobs with `secret_output: true` (`credentials/material`).

**Does not show.** That a plugin being listed means the captured kernel is supported; that a malfind result is injection.
