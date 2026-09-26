---
id: timeline/linux
title: A Linux timeline is several clocks, not one sorted CSV
when: Building or checking the chronology of a Linux compromise.
needs: [triage/system-profile, logs/auth, logs/journal, filesystem/storage]
tools: [linux_triage, timeline_super, timestamp_decode]
requires_host: [log2timeline, psort]
---

Build independent layers before merging them:

1. File-system MACB times from the disk catalogue. On ext, `ctime` is inode
   change, not creation; `crtime` is creation where present. XFS and Btrfs have
   different metadata and snapshot semantics.
2. Syslog/auth text. Traditional syslog timestamps have no year or offset, so
   keep the source text and state the year and timezone you applied.
3. The journal. Keep `_BOOT_ID` and the realtime timestamp; boot grouping is
   what survives a clock correction.
4. Package-manager, cron/systemd, shell-history, wtmp/btmp/lastlog, web and
   container records from `linux_triage`. A shell command without a recorded
   timestamp has sequence only.
5. A Plaso storage file from `timeline_super` when its parser coverage adds
   value. Keep the storage file and export; a sample returned inline is not the
   timeline.

Normalise to UTC only after preserving the original value and source timezone.
Sort equal timestamps deterministically but do not invent an order within their
resolution: syslog may have seconds, ext may have nanoseconds, and a date-only
package record may describe a whole day. Correlate important events across two
independent sources and state disagreements rather than choosing the cleaner
one. An empty parser result supports an absence only when its paths, time range,
allocated/deleted scope and parser errors are all recorded.
