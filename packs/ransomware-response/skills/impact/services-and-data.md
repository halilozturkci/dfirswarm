---
id: impact/services-and-data
title: Services, dependencies, datasets and outage
when: You state what the incident did to services, data and people, beyond a file count.
needs: []
tools: [ransomware_scope_report]
requires_host: []
---

Use when you state what the incident did to services, data and people. Not for the notification clocks (`reporting/notification-register`) or the report's conclusions (`reporting/conclusions-and-controls`).

**Effects, not file counts.** Keep apart confidentiality (what could be read or was
taken), integrity (what was changed or destroyed) and availability (what could not be
used, and for how long). A number of encrypted files is none of them: one database
can hold the effect of a million files, and a million files can hold none.

**Services and dependencies.** For each affected service name what it depends on
(identity, storage, network, backup, other services), the safety consequence if there
is one, and the outage as a start and an end with the source of each time. A service
that came back was available again; it was not shown to be sound.

**Datasets and populations.** Name each dataset, whose data it holds and how many
people or customers that is, with the way the figure was reached. Give a range where
the evidence gives one.

**Estimated, tested, confirmed.** Mark every figure as one of the three. Estimated
is reasoned from inventories; tested is a sample examined, with its denominator;
confirmed is checked against the objects themselves. `ransomware_scope_report`
counts what the sealed outputs of several hosts say, per host with denominators
(`coverage_statement`, `assessed_against_unassessed`,
`candidate_against_validated`). A host whose `scope` is `unknown` has no figure, a
`conflict` is not added in, and the report states no `estate_wide_percentage`: do
not write one from it.

**Materiality.** No tool decides it. The people accountable decide whether an effect
is material, with this evidence in front of them.

**Shows.** Which effects, services and datasets the evidence supports, and how firmly.

**Does not show.** A count of encrypted files does not show an effect; a restored
service does not show sound data; a tested sample does not show the population.

Record: per effect and service the dependency, the interval with its sources, the
dataset and population, and whether each figure is estimated, tested or confirmed.
Sensitive output: personal data stays in the evidence store; cite counts and
references, never the data.
