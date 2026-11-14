---
id: beacons/periodicity
title: Testing a series of connections for periodicity
when: You suspect something calls home on a schedule, or a first pass found nothing.
needs: [capture/what-you-have]
card: pcap_summary {"path": "<capture>", "with_syn_times": true} gives SYN events, not connection starts; with syn_times_omitted the series is syn_times_file. beacon_score {"timestamps_file": "<file>"} needs zoned times; status partial: a value unscored or its clock ran out. Silence needs window_end and sensor_coverage_confirmed. Does not show: purpose, malice or other channels.
tools: [beacon_score, pcap_summary, conn_series]
requires_host: []
---

Use when you test repeated connections for regularity. Not for detection: a regular series is a lead, and many calls home are neither regular nor repeated.

1. **Command and control** may show in content, in metadata or in timing; it may be one long connection with no schedule. Update checks, telemetry, NTP, revocation checks, mail polling and monitoring are more regular than most malware. Compare intervals and sizes with comparable hosts and services; a tight interval or small exchange alone proves nothing.
2. **Build the series first.** Define the event (a SYN observation, a DNS query, a proxy request, an application transaction), the direction, the endpoint pair or service, the observation window and the sensor. For TCP, `pcap_summary` with `with_syn_times` gives SYN *event* times per tuple: `syn_observations` counts every SYN-only packet, a SYN resent with the same sequence number within 120 s of its event's first is folded in (`syn_folded`), a reused tuple merges earlier uses, and a row keeps at most 10,000 events (`syn_unique_is_lower_bound`). Inline are the first 100 times: with `syn_times_omitted`, the series is `syn_times_file` (and the TSV). Persistent TCP, UDP or QUIC has no SYN: use transactions or logs. From a Zeek `conn.log` or a capture, `conn_series` writes the unique connections and a `timestamps_file` for `beacon_score` (each time is when a connection began, not an exchange).
3. Give `beacon_score` zoned times (`assume_utc` only if known UTC; each is counted) and at least the distinct events it asks for, up to 3,000,000 in a file. Keep the whole input; account for duplicates and known gaps. A value it cannot score is named by position and reason, never printed; `status` is `partial` when one was not scored, or its clock ran out and only the values read were measured (reading gets two fifths of `max_seconds`).
4. Read it as description: median interval, MAD, `mad_over_median` (not a configured jitter or a probability), a shape name (the tool's convention), `event_density_ratio` (below 1 does not show missing events).
5. **Stopping.** `long_final_gap` is a last interval over four times the median that ended in another event: a series that resumed. Silence needs `window_end` and `sensor_coverage_confirmed`, and is a bounded negative about this series only, not that a channel ended or moved.
6. Corroborate before calling it a finding: a destination with no business, a process that should not talk, a wrong certificate or name, a user agent seen nowhere else.

Shows: how tightly one defined series clusters. Does not show: purpose, malice or the absence of other channels. Record: event definition, window, sensor, counts in and rejected, the tool's numbers, the comparison you made.
