---
id: timeline/clocks
title: Timestamp semantics, zones and clock uncertainty
when: Before a number becomes a time in the ledger, or sources disagree.
needs: []
tools: [timestamp_decode]
requires_host: []
---

Use when you turn a stored value into a time, convert a zone, or order events across clocks. Not for choosing parsers for a machine timeline (`timeline/super`) or for an artefact's field layout (the artefact's own skill).

**Keep, per timestamp:** the raw value, the field name, its encoding, epoch, unit and resolution, its zone semantics (UTC, a fixed offset, local time of an unknown zone, none), the source and locator, and what event the field describes (a file's modification is not a person's action). Convert last; keep the raw value beside the result.

**Epoch.** The artefact's schema decides which clock wrote a number, never the reading that looks plausible. `timestamp_decode` lists what the number would be under each epoch in common use (Unix in four resolutions, FILETIME, WebKit, Apple, HFS+, OLE, DOS), exactly (fractions to the nanosecond, the rest in `remainder_s`). It applies no zone or daylight-saving rule (DOS and OLE carry none). The plausible range is a ranking aid, not evidence: for an old, sentinel or unusual value keep every reading (the default) and decide from the schema.

**Zone.**
- UTC, offset-bearing and local-without-zone are three kinds of value. Do not convert a value already in UTC.
- A local time needs the zone and its rule on the event's date, daylight saving included. Find the zone where the artefact family keeps it (the registry on Windows; `/etc/localtime` and configuration on Linux) and record where. A present-day setting is not proof of a past one, and one host setting does not fit every source.
- A repeated local hour (a daylight-saving change) is ambiguous: keep both readings until another source chooses. A local time in the skipped hour does not exist: it points to a wrong zone, rule or clock; record it as found.
- A stamp with no year (traditional syslog) needs a year basis: record the text, the basis and the zone applied.
- When UTC cannot be established, record the observation and the limit, not a UTC time you lack.

**Resolution and order.** Seconds (syslog), 2 seconds (DOS), 100 ns (FILETIME), a whole day (a date-only record). Invent no order inside a resolution: sort equal times by a fixed rule and say which.

**Drift and changes.** Only if two sources or hosts disagree on when, a clock may have been set or may drift, or NTFS `$STANDARD_INFORMATION` and `$FILE_NAME` times differ: `timeline/clocks-drift`.

**Record.** The zone and its source, the year basis, why the schema fixes the epoch, the uncertainty, what would disprove the reading.

**Does not show.** A timestamp shows what a clock the artefact trusted wrote into that field, not when a person acted, that two clocks agree, or that a time order is causal.
