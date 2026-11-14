---
id: timeline/linux
title: Linux chronology across clocks and families
when: Building a reproducible timeline from independent evidence layers.
needs: []
card: Build independent layers before merging. timeline_super {"source": "<image>", "out_dir": "work/<your id>/<name>", "parsers": "<parser list>"}: complete is not coverage (the storage file's processing report is), an empty timeline is partial, the inline sample is not the timeline. linux_triage: record functions, dissect.target version and each status; it has no audit family and reads no RPM database. auth_log rows keep their year and zone basis. Does not show: that an event happened, or that two close records are linked.
tools: [auth_log, linux_triage, timeline_super]
requires_host: [log2timeline, psort]
---

Use when you merge Linux evidence into a timeline. Not for normalising stamps and correlating events (`timeline/linux-normalise`, only if the layers are built).

Build independent layers before merging them:

1. Filesystem MACB times from the disk catalogue. On ext, `ctime` is the inode change time, not creation; `crtime` is creation where the inode holds it. XFS and Btrfs have different metadata and snapshot semantics (`filesystem/storage`).
2. Text logs (auth, syslog), each with its timestamp format. A traditional stamp has no year and no zone: keep the source text and state the year basis and zone you applied (`auth_log` records both).
3. The journal: `__REALTIME_TIMESTAMP`, `__MONOTONIC_TIMESTAMP` and `_BOOT_ID` side by side. Within a boot use monotonic time to look for wall-clock discontinuities; across boots and hosts establish independent anchors and carry the uncertainty (`logs/journal`).
4. Audit, package-manager, scheduler, session, application, cloud and container records, and the families `linux_triage` produces. Record its selected function list, the dissect.target version, each function's status and stderr: its sessions family is classic wtmp, btmp and lastlog, its package family is the Debian-family status file and package-manager logs, it has no audit family, and a clean run is no evidence of RPM, newer accounting or full container coverage. A shell command with no recorded time has sequence only, and the sequence can reflect when a session flushed or merged its file, not when the command ran.
5. A Plaso storage file from `timeline_super` where its parser coverage adds value. Run `log2timeline` and `psort` through that wrapper or directly, record the parser names actually available in that version, the timezone, the filters, the errors, the storage file and the complete export. A parser succeeding is not an evidence family being complete, and a sample returned inline is not the timeline.

Shows: what each layer recorded, side by side. Does not show: that an event happened because a record names it, or that two records a second apart are causally linked. Record: per layer the source, format, clock, year and zone basis, parser or function statuses and the stored export.

Sensitive output: `auth_log` and `linux_triage` outputs hold sudo command lines, names typed at a prompt, shell histories and log messages that can contain a password or a token. Run them as jobs with `secret_output: true`, cite the file and line, and carry no text or hash of a value into the timeline: a timeline row says what happened and where it is recorded.
