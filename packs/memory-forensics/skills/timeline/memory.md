---
id: timeline/memory
title: Times in a memory capture and what each one dates
when: A time from memory goes on a timeline, or is ordered against disk or logs.
needs: [timeline/clocks]
card: mem_profile {"path": "<crash dump>"} gives the header time raw (system_time_filetime) beside the converted one: it dates when the dump was written, not the acquisition or the last activity. Keep each time's kind (acquisition bounds, guest clock, dump header, saved state, object creation) with its raw value, epoch and unit. Order only within one clock; join guest to host only with a measured offset and its uncertainty. A time after acquisition end or before boot is a fault or smear to explain, not an event. Does not show: that acquisition time is guest time, or when a process acted.
tools: [mem_profile]
requires_host: []
---

Use when a time found in or around a memory capture goes into a timeline. Not for the semantics of a stored timestamp (`timeline/clocks`) or for network time fields (`network/timestamps-dns`).

A memory capture holds several times and each dates something different. Keep the kind with the value:

- **Acquisition start and end**: from the acquisition record or the tool's log, on the operator's clock. They bound the capture; memory is not read at one instant.
- **Guest clock**: the machine's own time at some point. A crash dump's header time is given by `mem_profile` raw (`system_time_filetime`) beside the converted time. The guest clock can be wrong, in another zone or changed; give its offset to the host clock, measured, with its uncertainty.
- **Dump-header time**: when the dump was written. It is not the acquisition time and not the last activity.
- **Saved-state time**: a hibernation file or a VM's saved state dates the moment it was saved, not the moment of acquisition (`triage/container-details`).
- **Process and network creation times**: the time the object was created, on the guest clock, read from the structure. A remnant found by a scan carries what the stale object held (`processes/kernel-integrity`).
- **Ranges under smear**: the system kept running while pages were copied, so structures read from different ranges of one capture may describe different moments. Do not treat them as simultaneous; list the ranges.

**Decision rules.**
1. Keep the raw value, the field name, the epoch and the unit, and convert last (`timeline/clocks`).
2. Order events only within one clock. Join the guest clock to the host's only with a measured offset and its uncertainty.
3. A time after the acquisition end, or before the machine's boot, is a clock fault, a smear or a wrong reading to explain, not an event.
4. A creation time says when the object began, not when it did anything.

**Shows.** Which clock a time belongs to, what it dates, and how far it can be trusted.

**Does not show.** That the acquisition time is the guest time; that the dump-header time is the last activity; that a creation time dates the activity of the process.

Record: the value as stored, the kind above, the clock and its offset with the uncertainty, the ranges it was read from, and the method.
Sensitive output: times and offsets only; no memory content in a post.
