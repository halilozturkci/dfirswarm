---
id: network/state
title: Network objects, ownership and timestamp limits
when: You need connections, listeners or an address from memory, or an address to tie to a host artefact.
needs: [processes/injection]
tools: [mem_fs, ioc_scan]
requires_host: [memprocfs, vol]
---

Memory may preserve current network structures and remnants of earlier ones,
observed across the acquisition interval rather than at one instant (the capture is
a smear: `acquire/images`).

**Which view.** On a supported Windows image compare `windows.netstat.NetStat`,
which walks the kernel's network tracking structures, with
`windows.netscan.NetScan`, which scans for network objects (both run through
`vol`; `triage/volatility` has the symbols they need). A scan result alone does
not say an object was live or freed. On Linux use `linux.sockstat.Sockstat` where
the installed plugin supports the captured kernel. With MemProcFS (`memprocfs`)
the network tables are files; `mem_fs` can list and export them
(`processes/injection` has the lifecycle). For each object record the method, the
object's address and layer, the protocol and address family, both endpoints, the
state, the owning process and what the engine could not validate. A live-or-freed
statement needs a view that says it.

    established connections   endpoints, state, owning process
    listeners                 a port bound by something unexpected is a lead
    other remnants            objects the scan found that the lists did not

`ioc_scan` finds a literal address or name in the bytes, in ASCII and UTF-16LE, with
offsets; it is not a parser, and it does not tell an endpoint from a log line. Its
answer carries snippets of the surrounding bytes: treat them as sensitive output
(below).

**A timestamp is what the field says.** A time the parser decoded belongs to the
field it came from: a creation time is not a close time, a last-activity time or
proof that the connection lasted until the capture. Check it against the process's
lifetime, the capture time and independent telemetry; a partly overwritten or
unvalidated structure keeps its uncertainty. Record the raw value, its
interpretation and the clock it came from, and do not invent a time for a remnant
that has none.

**Corroboration.** Report a validated memory observation with its limits even when no
disk artefact backs it, and look for packet captures, firewall or proxy events, DNS
records and host telemetry. Say what each source shows (configuration, resolution,
connection activity, transferred content): a firewall rule is configuration, not a
connection. An address in memory with nothing else behind it is a lead, and the
missing corroboration limits the behavioural conclusion; it does not erase the
structure.

**The DNS cache.** A validated cache entry is retained resolution data. It does not
show that a particular process contacted the name, or that a person visited it:
account for application-local caches, encrypted DNS, shared addresses, aliases,
expiry and stale entries, and establish which resolver or application owned the
cache. This pack has no cache parser: if you have none, record the route as
unexamined, and do not assume every Linux host runs systemd-resolved or that every
relevant name is in one Windows service.

**A listener is not a backdoor.** Plenty of legitimate software listens. What makes
one interesting is the process that owns it, where that process runs from, and
whether anything on disk explains it.

**Sensitive output.** Addresses, URLs and snippets can carry tokens, user names and
secrets: run `ioc_scan`, and `mem_fs` text or export, as jobs with
`secret_output: true`, and describe what they show without copying a secret
(`credentials/material`).

**Does not show.** A person at the other end, an intent, a transfer of data, a
connection's duration, or that a freed structure was ever connected; none follows
from an endpoint in memory alone.
