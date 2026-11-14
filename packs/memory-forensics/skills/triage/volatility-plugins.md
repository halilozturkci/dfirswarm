---
id: triage/volatility-plugins
title: Volatility plugins by operating system
when: Choosing Windows, Linux or macOS plugins, or the option that writes a region out.
needs: []
card: mem_registry {"path": "<image>"} lists hives; {"mode": "printkey", "offset": "<offset>", "key": "<key>"} reads one key. partial: pages missing, an unnamed hive or a limit; complete is a heuristic. SAM and SECURITY: {"write_values": true} in a secret_output job. Does not show: kernel support or injection.
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
    windows.netscan    a scan for network objects
    windows.malware.malfind.Malfind   candidate private executable regions
    windows.vadinfo    the region boundaries and protections behind a candidate
    windows.handles    what a process could reach
    windows.modules / windows.dlllist   kernel and per-process modules
    windows.svcscan    registered and residual services

`mem_registry` lists the hives and reads one key of one hive through `vol`, offline; it withholds credential-named values and refuses SAM and SECURITY outside a secret-output job.

As of October 2026, in 2.28.2, the older `windows.malfind` and `linux.malfind`
names are deprecated forwarding classes of the `.malware.malfind` plugins (a
receipt that names the old one ran the alias); the Windows one writes the regions it finds with `--dump`. Options and output change between versions: check `vol <plugin> --help`,
and `vol --help` for the plugin list.

**Linux.** There is no exhaustive public cache: the ISF must match the exact
kernel build and architecture; a nearby distribution version is not a
substitute (the cache claim is UNVERIFIED here). Establish the kernel banner and a matching ISF before any
symbol-dependent analysis; as of October 2026, in 2.28.2, the plugins include
`linux.pslist.PsList`, `linux.pstree.PsTree`, `linux.lsof.Lsof`,
`linux.sockstat.Sockstat`, `linux.envars.Envars`, `linux.bash.Bash` and
`linux.malware.malfind.Malfind`, whose option for writing regions is
`--dump-regions` (not the Windows `--dump`; it has its own `--dump-maxsize`, 1 GB
by default). This pack supplies no Linux or macOS ISF set; `isf_intake` converts
the operator's Linux debug material, ready only on an exact banner match. Record the provenance;
validate the kernel's identity and architecture. Without the matching table, report
symbol-dependent Linux analysis as not performed. A plugin being listed does not show support. macOS: no support claim for any version (`symbols/macos`); an
unsupported target is reported as unexamined.

**Sensitive output.** `windows.cmdline`, `linux.envars`, `linux.bash` and every plugin that dumps a region can expose credentials: jobs with `secret_output: true` (`credentials/material`).

**Does not show.** That a listed plugin means the captured kernel is supported; that a malfind result is injection.
