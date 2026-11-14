---
id: network/state
title: Network objects and their owners in memory
when: You need connections, listeners or an address from memory, or one to tie to a host artefact.
needs: []
card: ioc_scan {"path": "<image>", "needles": "<address>|<name>"} finds literal bytes (as given and UTF-16LE) with offsets: it is not a parser, and a hit is not an endpoint. Connections and listeners come from an engine view (vol, or MemProcFS tables via mem_fs); a scan alone does not say live or freed. A listener is a lead. Does not show: a person, intent, a transfer or a duration.
tools: [mem_fs, ioc_scan]
requires_host: [memprocfs, vol]
---

Use when you need connections, listeners or an address from memory. Not for dating them or for DNS cache entries (`network/timestamps-dns`).

Memory may hold current network structures and remnants of earlier ones, seen
across the acquisition interval, not at one instant (a smear: `acquire/images`).

**Which view.** On a supported Windows image compare `windows.netstat.NetStat`,
which walks the kernel's network tracking structures, with
`windows.netscan.NetScan`, which scans for network objects (both run through
`vol`; `triage/volatility` has the symbols they need). A scan result alone does
not say an object was live or freed. On Linux use `linux.sockstat.Sockstat` where
the installed plugin supports the captured kernel. With MemProcFS (`memprocfs`)
the network tables are files; `mem_fs` can list and export them
(`processes/preserve-regions` has the lifecycle). For each object record the method, the
object's address and layer, the protocol and address family, both endpoints, the
state, the owning process and what the engine could not validate. A live-or-freed
statement needs a view that says it.

    established connections   endpoints, state, owning process
    listeners                 a port bound by something unexpected is a lead
    other remnants            objects the scan found that the lists did not

`ioc_scan` finds a literal address or name in the bytes, in ASCII and UTF-16LE, with
offsets; it is not a parser, and it does not tell an endpoint from a log line. Treat the bytes around a hit as sensitive output (below).

**Corroboration.** Report a validated memory observation with its limits even when no
disk artefact backs it, and look for packet captures, firewall or proxy events, DNS
records and host telemetry. Say what each source shows (configuration, resolution,
connection activity, transferred content): a firewall rule is configuration, not a
connection. An address in memory with nothing else behind it is a lead, and the
missing corroboration limits the behavioural conclusion; it does not erase the
structure.

**A listener is not a backdoor.** Plenty of legitimate software listens; what matters is the
owning process, where it runs from, and whether anything on disk explains it.

Only if you quote a time from a network object or read a DNS cache entry: `network/timestamps-dns`.

**Sensitive output.** Addresses, URLs and snippets can carry tokens, user names and secrets: run `ioc_scan`, and `mem_fs` text or export, as jobs with
`secret_output: true`, and describe what they show without copying a secret
(`credentials/material`).

**Does not show.** A person at the other end, an intent, a transfer of data, a
duration, or that a freed structure was ever connected; none follows from an endpoint alone.
