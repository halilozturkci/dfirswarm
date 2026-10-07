---
id: timeline/linux
title: Linux chronology across clocks and evidence families
when: Building a reproducible timeline with source dependencies and uncertainty preserved.
needs: [triage/system-profile, logs/auth, logs/journal, filesystem/storage]
tools: [auth_log, linux_triage, timeline_super, timestamp_decode]
requires_host: [log2timeline, psort]
---

Build independent layers before merging them:

1. Filesystem MACB times from the disk catalogue. On ext, `ctime` is the inode change time, not creation;
   `crtime` is creation where the inode holds it. XFS and Btrfs have different metadata and snapshot
   semantics (`filesystem/storage`).
2. Text logs (auth, syslog), each with its timestamp format. A traditional stamp has no year and no zone:
   keep the source text and state the year basis and zone you applied (`auth_log` records both).
3. The journal: `__REALTIME_TIMESTAMP`, `__MONOTONIC_TIMESTAMP` and `_BOOT_ID` side by side. Within a boot use
   monotonic time to look for wall-clock discontinuities; across boots and hosts establish independent anchors
   and carry the uncertainty (`logs/journal`).
4. Audit, package-manager, scheduler, session, application, cloud and container records, and the families
   `linux_triage` produces. Record its selected function list, the dissect.target version, each function's
   status and stderr: its sessions family is classic wtmp, btmp and lastlog, its package family is the
   Debian-family status file and package-manager logs, it has no audit family, and a clean run is no evidence
   of RPM, newer accounting or full container coverage. A shell command with no recorded time has sequence only,
   and the sequence can reflect when a session flushed or merged its file, not when the command ran.
5. A Plaso storage file from `timeline_super` where its parser coverage adds value. Run `log2timeline` and
   `psort` through that wrapper or directly, record the parser names actually available in that version, the
   timezone, the filters, the errors, the storage file and the complete export. A parser succeeding is not an
   evidence family being complete, and a sample returned inline is not the timeline.

Keep each original timestamp, its encoding, resolution, source clock, the inferred year and zone and the
uncertainty beside the normalised UTC value (`timestamp_decode` decodes a raw number into every reading it knows: choose the
epoch from the source's format, never from the reading that looks plausible). Normalise only after preserving the original and the source zone. Where a daylight-saving transition makes
a local time ambiguous, keep both readings until evidence chooses. Record clock steps, synchronisation events,
suspend and resume, and snapshot rollback where the evidence shows them. Sort equal timestamps
deterministically and do not invent an order inside their resolution: syslog has seconds, ext has nanoseconds in
the inode and not necessarily in its accuracy, and a date-only package record may describe a whole day.

Correlate material events across two independent sources and state disagreements instead of choosing the
cleaner one. A journal message and the syslog copy forwarded from it are one observation, not two. An empty
parser result supports an absence only when its paths, time range, allocated and deleted scope and parser errors
are all recorded.

**Does not show.** That an event happened because a record names it, or that two records a second apart are
causally linked.
