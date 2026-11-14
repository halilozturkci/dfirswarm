---
id: timeline/linux-normalise
title: Normalising and correlating a Linux timeline
when: Merging layers into UTC, ordering equal stamps and weighing a correlation or an absence.
needs: []
card: timestamp_decode {"value": "<raw number>"} lists every reading: choose the epoch from the source's format, never the plausible reading. Keep the original value, encoding, resolution, clock, zone and year basis beside the UTC value; normalise only after. Keep both readings of a local time made ambiguous by a daylight-saving change. Do not order inside a source's resolution: sort ties deterministically and say the rule. A journal message and its forwarded syslog copy are one observation. An empty parser result supports an absence only with its paths, range, scope and errors recorded. Does not show: that an event happened, or that two close records are linked.
tools: [timestamp_decode]
requires_host: []
---

Use only if the layers exist and you normalise or correlate them. Not for building the layers (`timeline/linux`).

Keep each original timestamp, its encoding, resolution, source clock, the inferred year and zone and the uncertainty beside the normalised UTC value (`timestamp_decode` decodes a raw number into every reading it knows: choose the epoch from the source's format, never from the reading that looks plausible). Normalise only after preserving the original and the source zone. Where a daylight-saving transition makes a local time ambiguous, keep both readings until evidence chooses. Record clock steps, synchronisation events, suspend and resume, and snapshot rollback where the evidence shows them. Sort equal timestamps deterministically and do not invent an order inside their resolution: syslog has seconds, ext has nanoseconds in the inode and not necessarily in its accuracy, and a date-only package record may describe a whole day.

Correlate material events across two independent sources and state disagreements instead of choosing the cleaner one. A journal message and the syslog copy forwarded from it are one observation, not two. An empty parser result supports an absence only when its paths, time range, allocated and deleted scope and parser errors are all recorded.

Shows: a reproducible order with its uncertainty. Does not show: that an event happened because a record names it, or that two records a second apart are causally linked. Record: original value, encoding, resolution, clock, zone and year basis, the tie-break rule, each disagreement.

Sensitive output: a timeline row carries no text or hash of a value; it says what happened and where it is recorded.
