---
id: triage/clocks-boots
title: Clocks, zones and boot history
when: Fixing the zone and year for timestamps and building the boot history.
needs: []
card: timestamp_decode {"value": "<raw>"} gives candidates: choose the epoch from the source's format. Take a record's zone from the configuration and corroboration in force on that date, not /etc/timezone alone (today's setting); apply one stated correction per source. Build boots from every source: journal boot ids, BOOT_TIME records of utmp_parse {"path": "<wtmp>", "types": ["BOOT_TIME"]}, a SQLite accounting database, boot and shutdown logs, captured uptime, hypervisor or cloud records; wtmp is neither guaranteed nor exhaustive. Does not show: a boot no source you read recorded, or an earlier date's zone from today's setting.
tools: [timestamp_decode, utmp_parse]
requires_host: []
---

Use only if you convert timestamps or need the boots. Not for the identity files (`triage/identity-files`) or for a source's own clock rules (`logs/auth`, `logs/journal`).

**Clocks and zones.** Read the timestamp format and logging template of each source. Traditional syslog omits the year and the offset; an RFC 3339 stamp may carry both; journal realtime is epoch-based wall time from a clock that may have been wrong or adjusted. For a record with no zone, take the zone in force on that date from the configuration and from corroborating records, not from `/etc/timezone` alone: it is today's setting and says nothing of daylight-saving history. Decode a raw numeric stamp with `timestamp_decode`, choosing the epoch from the source's format. Apply one correction per source, state which, and do not convert every artefact with one offset. Say in the report which zone and year you applied and to which sources.

**Boot history.** Build it from every source that has one: journal boot ids (`logs/journal`), the `BOOT_TIME` records `utmp_parse` reads from classic wtmp, a SQLite accounting database (see `accounts/users`), boot and shutdown logs, captured uptime, and hypervisor or cloud records. State each source's retention and what was collected: wtmp is neither guaranteed nor exhaustive, and a reboot that left no record in one source is not shown not to have happened.

Shows: the zone, year and epoch assumption per source, and the boots each source records. Does not show: a boot that left no record in the sources you read, or the zone of an earlier date from today's setting. Record: per source the format, epoch, zone and year applied and on what basis, and each boot source's retention.

Sensitive output: none beyond timestamps and boot ids.
