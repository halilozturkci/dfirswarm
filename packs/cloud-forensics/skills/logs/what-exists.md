---
id: logs/what-exists
title: What a cloud export covers, and what silence can say
when: Supplied cloud or SaaS logs are the evidence, and an answer or a negative depends on what they hold.
needs: [evidence/verify]
tools: []
requires_host: []
---

Use when the evidence is cloud or SaaS log exports examined offline and you must say what they cover. Not for parsing one source (use the provider's skill) or for disk, memory or network evidence.

**Boundary.** Examine what was supplied. Never authenticate to a tenant, use a recovered credential or change a configuration. A missing export is an acquisition ask (close the lead needs_operator with an `ask` of kind acquisition), never something you fetch.

**Record per source, before any negative** (a `kind=coverage` entry): tenant, account or project; region or subscription; event categories; the interval requested and the earliest and latest event returned; when the export started and finished; who collected it and with what permission; the query and its exclusions; how pages and result limits were handled; counts returned; collector errors. What was returned is not what was requested: a gap at the edge of the window says nothing about an actor.

**Three times.** An event has a time it happened, a time the provider ingested it and a time it was exported. Delivery delay varies; an event's `clock` says which of the three its time is; do not read the last returned row as the moment activity stopped. If a later overlapping export was supplied, compare it for late arrivals; otherwise name the unsettled end as a limitation.

**Hashes.** A file hash shows the bytes are those recorded when it was taken. It does not show the provider made them, or that every relevant event was exported. Keep hashes of the originals apart from hashes of parsed outputs, and cite both.

**Configuration.** A snapshot shows state at its collection time; what changed needs an earlier state, a history or a change record. A product default is not this tenant's setting, and a retention figure from memory is not evidence: take retention from the supplied settings or the collection record, or say it is unknown.

**A negative** is "No evidence of X was found in source S over period P, as collected by Q"; `detection_opportunity` says whether S would have recorded X. Disabled sources, selectors, exclusions, expired retention, failed delivery and omitted acquisition are different causes of the same silence: keep them apart, and look at the other supplied sources before answering not determinable.

**Does not show:** that an event was or was not logged; that the tenant's retention covered the incident; that a complete export is a complete record.

**Sensitive output:** exports hold personal data and can hold secrets. The provider skills say which tool needs a `secret_output: true` job.

Only if you must list which source families to ask for: `logs/sources`.
