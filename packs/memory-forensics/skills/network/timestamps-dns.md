---
id: network/timestamps-dns
title: Timestamps and DNS cache entries from memory
when: A network object carries a time, or you read a DNS cache entry.
needs: []
tools: []
requires_host: []
---

Use only if a network object carries a time you will quote, or you read a DNS cache entry. Not for finding the objects (`network/state`).

**A timestamp is what the field says.** A time the parser decoded belongs to the
field it came from: a creation time is not a close time, a last-activity time or
proof that the connection lasted until the capture. Check it against the process's
lifetime, the capture time and independent telemetry; a partly overwritten or
unvalidated structure keeps its uncertainty. Record the raw value, its
interpretation and the clock it came from, and do not invent a time for a remnant
that has none.

**The DNS cache.** A validated cache entry is retained resolution data. It does not
show that a particular process contacted the name, or that a person visited it:
account for application-local caches, encrypted DNS, shared addresses, aliases,
expiry and stale entries, and establish which resolver or application owned the
cache. This pack has no cache parser: if you have none, record the route as
unexamined, and do not assume every Linux host runs systemd-resolved or that every
relevant name is in one Windows service.

**Does not show.** That a creation time is a close time or proves the connection lasted until the capture; that a cache entry means a process contacted the name or a person visited it.

Record: the raw time value, its interpretation and its clock; which resolver or application owned a cache; a DNS route you could not examine, as unexamined.
Sensitive output: names and addresses can carry tokens or user names; keep the scan output in a sealed job (`network/state`).
