---
id: scope/phase-timeline
title: Keeping a phase timeline of the incident
when: You order the incident's phases, or must say when it began and ended.
needs: []
tools: [ransomware_scope_report]
requires_host: []
card: ransomware_scope_report ({"timelines": [{"host": "<h>", "file": "<events.jsonl>"}]}, events {host, time, kind}, time in UTC ending in Z) gives each host's first and last event given: not the phases' start and end, and a host without a census is unknown. Keep first and last observed activity apart from the real start and end, and each original timestamp with its zone, clock offset and precision. Does not show: the start of the compromise, that the first encrypted asset was the first compromised, or the dwell time.
---

Use only if you order the incident's phases or must say when it began or ended. Not for the first-hour decisions (`scope/first-hour`).

**Keep a phase timeline.** Initial access, persistence and spread, staging,
possible exfiltration, recovery impairment, encryption and impact can overlap,
repeat or be absent. Record the first and last observed activity apart from the
real start and end, which may be unknown; the first encrypted asset is not
necessarily the first compromised one. Keep each original timestamp, its source
zone, clock offset and precision beside the UTC value. Do not infer dwell time
from a typical campaign, and do not treat encryption as the adversary's last
action.

`ransomware_scope_report` takes timelines of events (host, time, kind) with the
censuses and checks of several hosts by reference, and gives each host's first and
last event beside its denominators. Those are the events given, not the phases'
start and end; a host without a census is unknown.

**Does not show.** That the earliest observed artefact is the start of the compromise; that the first encrypted asset was the first compromised; that encryption was the last action or that the dwell time matches a typical campaign.

Record: first and last observed activity per phase, each original timestamp with its source zone, clock offset and precision beside the UTC value.
Sensitive output: none; the timeline carries times and asset names, never note values or credentials.
