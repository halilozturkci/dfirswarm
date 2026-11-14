---
id: reporting/conclusions-and-controls
title: Conclusions by phase, and control findings
when: Writing conclusions by phase, a negative exfiltration finding or insurance findings.
needs: []
tools: [ransomware_scope_report]
requires_host: []
card: Write each conclusion as established, partial, bounded negative or not determinable, with sources, method, scope and contrary evidence. ransomware_scope_report gives scope per host with denominators: a host with no census is unknown and no estate-wide percentage is stated; do not write one. A negative exfiltration finding names the sources, interval, gaps and whether the transfer would have appeared there. Does not show: the start of the compromise, or that a control was missing everywhere.
---

Use only if you write the report's conclusions by question and phase, a negative exfiltration finding or the insurance and control findings. Not for the notification clocks (`reporting/notification-register`).

**Report by question and phase.** Cover initial access, persistence and spread,
staging, possible exfiltration, recovery impairment, encryption, service impact,
containment and recovery. Phases can overlap, repeat or be absent. The earliest
observed artefact is not the start of the compromise, and encryption need not be
the adversary's last action. For each material conclusion give the source
references, the method and scope, what was observed and what inferred, the
confidence and its reason, the contrary evidence, the limitations and what would
change the answer. Use the outcomes the evidence supports: established, partial,
bounded negative, not determinable.

For the scope behind a conclusion across hosts, `ransomware_scope_report` counts what
the sealed outputs say, per host and with denominators. A host with no census is
unknown, and it states no estate-wide percentage: do not write one from it.

A negative exfiltration finding names the sources, systems, interval, coverage
gaps and the detection opportunity: whether the suspected transfer would have
appeared in that source. "Logs were present" is not a detection opportunity.

**Insurance and control findings.** Describe the control coverage, its
exceptions and the authentication route in use at the time. An exception on one
route does not show that the whole organisation lacked the control. Keep
technical findings apart from coverage decisions, and documented costs apart from
estimates.

**Does not show.** That the earliest observed artefact is the start of the compromise; that encryption was the adversary's last action; that "logs were present" is a detection opportunity; that a control exception on one route means the whole organisation lacked the control.

Record: per material conclusion the source references, method and scope, observed against inferred, confidence and its reason, contrary evidence, limitations and what would change the answer.
Sensitive output: conclusions cite note ids, offsets and sealed job references, never note text, identifiers or credentials (`reporting/for-regulators`).
