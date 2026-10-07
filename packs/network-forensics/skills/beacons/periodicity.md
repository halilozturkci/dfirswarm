---
id: beacons/periodicity
title: Testing a series of connections for periodicity
when: You suspect something calls home on a schedule, or a first pass found nothing.
needs: [capture/what-you-have]
tools: [beacon_score, pcap_summary]
requires_host: []
---

Use when you want to test repeated connections for regularity. Not for detection: a regular series is a lead, and many calls home are neither regular nor repeated.

1. **Command and control** may show in content, in metadata or in timing; it may be one long connection with no schedule. Update checks, telemetry, NTP, revocation checks, mail polling and monitoring are more regular than most malware. Measure intervals and transfer sizes against comparable hosts and services; a tight interval or a small exchange alone proves nothing.
2. **Build the series first.** Define the event (a SYN observation, a DNS query, a proxy request, an application transaction), the direction, the endpoint pair or service, the observation window and the sensor. For TCP, `pcap_summary` with `with_syn_times` gives SYN *observations* per tuple: a SYN sent again is counted unless you compare `syn_unique`, and a tuple used again later merges earlier uses. For persistent TCP, UDP or QUIC traffic there is no SYN: build the series from transactions or logs instead.
3. Give `beacon_score` times with a zone (`assume_utc` only if you know they are UTC; each such value is counted) and at least the distinct events it asks for. Keep the whole input; account for duplicates and known collection gaps.
4. Read it as description: median interval, MAD, `mad_over_median` (MAD over the median; not a configured jitter or a probability), a shape name that is a convention of the tool, and `event_density_ratio` (below 1 does not show events are missing).
5. **Stopping.** `long_final_gap` is a last interval over four times the median that ended in another event: a series that resumed. A statement about silence needs `window_end` and `sensor_coverage_confirmed`, and is a bounded negative about this series only; it does not show a channel ended or moved.
6. Corroborate before calling anything a finding: a destination with no business, a process that should not talk, a certificate or name that is wrong, a user agent seen nowhere else.

Shows: how tightly one defined series clusters. Does not show: purpose, malice or the absence of other channels. Record: event definition, window, sensor, counts in and rejected, the tool's numbers, the comparison you made.
