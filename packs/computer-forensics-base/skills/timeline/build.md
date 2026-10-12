---
id: timeline/build
title: Preserve timestamp meaning and uncertainty
when: Before interpreting or combining dated observations.
needs: [evidence/verify]
tools: [timeline_super, timestamp_decode]
requires_host: []
---

Put every dated fact in the ledger with `record` as you find it, not at the end.
This is the timeline the report cites, and it is yours: each row is a fact you
decided was worth recording, with a citation. The machine's version of the same
volume is `timeline/super` (`timeline_super`): it finds the window, and it is not
the report's timeline. `kind: event` needs an ISO 8601 UTC timestamp, the source
and how to check it, and `clock` says which clock the time came from. The harness
renders `ledger/ledger.md`; the report cites that file.

**Preserve before you convert.** For each timestamp keep the raw value, the field
name, its encoding, epoch, unit, precision and zone semantics, the source object
and record locator, and what event the field actually describes (a file's
modification is not an action by a person). Convert by the artefact's schema.
Use the zone rules in force on the event's date, daylight saving included: a
present-day zone setting is not proof of a past one, and one host setting does not
fit every source. Look for the zone where the artefact family keeps it (the
registry on Windows, system and application configuration and `/etc/localtime`
on Linux). Do not convert a value that is already UTC a second time. When UTC
cannot be established, record the observation and the timing limitation, and do
not write a UTC time you do not have. Keep intervals and date-only precision, and
do not invent an order between equal or overlapping times. A multi-machine case
rests on getting every log into one zone, so record each conversion and why.

**Wall clocks are not reliable witnesses.**

- A clock change can be logged, and the absence of a record of one does not show a
  stable clock. Correlate independent clock sources and record the offset or
  drift uncertainty. Use a monotonic order only within the sequence it is
  defined for (a boot, a journal instance, a retained USN or `$LogFile` range);
  do not merge unrelated sequences into one chronology.
- NTFS `$STANDARD_INFORMATION` and `$FILE_NAME` times are two sets of
  observations. Each can be altered by different means: when they disagree, say
  so, and treat neither as a trusted clock.
- Creation later than modification is a lead and not an error: copying,
  extraction, restoration and ordinary file system behaviour explain it too.

When a field holds a number and nothing says which clock wrote it, do not guess.
`timestamp_decode` lists what the number would be under each epoch in common use
(Unix in four resolutions, FILETIME, WebKit, Apple, HFS+, OLE, DOS), exactly: the
fraction is kept to the nanosecond, DOS and OLE readings carry no zone, and
plausibility is judged against a stated range and not the wall clock. It
generates candidates. The artefact's schema picks the clock, and a plausible date
is not a determination. Keep the raw value beside any converted time, and ask for
every reading (the default) when you are looking at an old, sentinel or unusual
value: a reading outside the plausible range can still be right.

Put confidence on a row: what you saw, what it implies, and what would disprove
it.

**Does not show.** A timestamp shows what a clock the artefact trusted recorded
in that field. It does not show when a person acted, or that two sources'
clocks agree.
