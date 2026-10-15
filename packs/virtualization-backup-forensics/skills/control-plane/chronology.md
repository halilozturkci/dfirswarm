---
id: control-plane/chronology
title: Clocks across hypervisor, backup and guest
when: Events from a hypervisor, a management server, a backup system and a guest must be ordered.
needs: [timeline/clocks]
tools: [backup_audit_normalise, timestamp_decode]
requires_host: []
mentions: [evtx_query]
---

Use when you order records from more than one plane. Not for one source's own timestamp format (`timeline/clocks`).

1. **One clock per source.** Write down, for each export, which machine wrote it, the zone and epoch it states, its resolution, and whether the value is a start, an end or a logging time. Do not assume a host log is UTC or local: read it from the export (a line that carries a zone, an epoch field, the host's recorded time settings).
2. **A task has several times.** A management record may carry queued, started and completed times, and the management server's time can differ from the host that ran the task. Keep them apart. `backup_audit_normalise` keeps the raw value beside `time_utc`, leaves a time with no zone un-derived, and converts one only with a fixed offset you declare (`time_zone_offset_minutes`; daylight saving is not accounted for).
3. **A guest clock is the guest's.** A guest can be set wrong or rolled back; a snapshot or restore can move it. A VM restored from a snapshot may carry earlier guest times after later host times. Order by host-side records, then reconcile guest times to them.
4. **Measure the offset between planes** from an event both record (a power operation, a snapshot, a login to a console) and state the uncertainty. An offset measured once does not hold across a restore, a resume or a long gap.
5. **Order only within uncertainty.** Two events closer than the offsets and resolutions allow are not ordered. Say "within N seconds" and cite both rows.
6. Use `timestamp_decode` for a value you identified; do not apply today's zone offset to a past date.

**Shows.** A sequence across planes within a stated uncertainty. **Does not show.** Which operator acted, or that an event preceded another when the clocks are unrelated.
**Record.** Per source: clock, zone, epoch, resolution, the offset you measured, how, and its uncertainty. For Hyper-V host events use the Windows pack's `evtx_query` when it is loaded.
**Sensitive output.** Run `backup_audit_normalise` as a job with `secret_output: true`. An object or job name is shown only if plain, else `<withheld: N bytes, field F>`; hosts, actors, actions and messages have token-shaped runs, user-info and the value after `password=`-style names withheld; a short plain password passes unseen.
