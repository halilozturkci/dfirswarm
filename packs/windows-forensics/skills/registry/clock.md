---
id: registry/clock
title: Windows clocks, zone rules, converting a time
when: You convert or compare a Windows time, or a local-time value enters a timeline.
needs: []
tools: [mft_records, regkv]
requires_host: [istat]
---

Use when any time is converted or joined. Not for what an artefact's time means beyond its clock (`filesystem/timestamps`, `antiforensics/timestamps-clock`).

- State what each artefact's time is before converting. UTC FILETIMEs need no zone: NTFS `$STANDARD_INFORMATION` and `$FILE_NAME` times, event log `SystemTime`, a registry key's last write, a Prefetch run time. FAT-family directory entries and shell-item DOS times are the local clock as written, to two seconds: the zone comes from that volume's own evidence. Keep the raw value beside every converted time (`mft_records` returns raw FILETIMEs and ISO 8601 UTC) and convert from the raw value, never from a rendering.
- Zone settings: `SYSTEM\ControlSet00n\Control\TimeZoneInformation` holds `TimeZoneKeyName`, `Bias`, `ActiveTimeBias`, `StandardBias`, `DaylightBias` (read with `regkv`). They are minutes with `UTC = local time + bias` (480 is UTC-8), the daylight component added on top of `Bias`. `ActiveTimeBias` is the offset in force when Windows last wrote it: it can be a daylight offset and says nothing about an earlier date.
- Never apply the zone read today to a past date. Take the rule for that date from a named source: the key `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones\<TimeZoneKeyName>\Dynamic DST` where present (per-year values in a REG_TZI_FORMAT structure, which this pack does not decode: name the decoder), or the zone database of a tool, with its version. A date inside a transition hour is ambiguous: give both readings.
- `istat` prints a file's times in the examiner host's zone unless told otherwise: run `istat -z UTC` (check each other Sleuth Kit program that prints times for the same option) and record the Sleuth Kit version and the exact invocation beside what you quote. A time copied from a rendering without that record is a local-time claim: convert it again from the raw value.
- Two machines or logs in one timeline: put every source in UTC first and state the zone taken for each local-time source and why.

Sensitive output: only time fields are read here (leave `mft_records` `with_resident` off; if it is on, a job with `secret_output: true`); `regkv` withholds by name and place only (`registry/readers`).
Shows: which clock a value is on and which rule converts it. Does not show: that the clock was right, or that today's zone applied then. Record: raw value, epoch or zone rule and its source, tool version and invocation.
