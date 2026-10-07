---
id: reporting/for-regulators
title: Evidence-led reporting and notification assessment
when: Preparing incident findings for legal, regulatory, insurance or executive review.
needs: [reporting/citations]
tools: []
requires_host: []
---

Keep one controlled evidentiary record and prepare each audience's disclosure from
it. Record every report's purpose, recipients, revision, approval and evidence
cut-off. A label ("privileged", "confidential") or a shared draft establishes
neither privilege nor confidentiality: the legal owner decides what goes to whom.

**Assess every harm, not only exfiltration.** Describe confidentiality, integrity
and availability effects separately, with the affected services, the categories
of personal data, the populations and the business consequences. As GDPR's definition of a
personal-data breach reads, and as similar laws may read, a loss of availability or
integrity can qualify, so ransomware can be reportable with no evidence that
anything left; check the definition against the current text. Uncertainty
about exfiltration does not justify postponing the notification assessment: it
goes into the report as a stated unknown.

**Keep the clocks separate.** For each time record who knew what, the supporting
record, the time zone, the clock uncertainty and who decided: when the incident
occurred, where that is established; detection; the organisation's awareness of
the incident; its awareness that personal data was affected; any classification
or materiality decision a regime asks for; each notification and each update. The
examiner's later confirmation of a fact is not the organisation's earlier
awareness of it, and the report does not substitute one for the other.

**Use a notification register.** One row for each duty that may apply: the legal
entity and its role (controller, processor, regulated entity, supplier);
jurisdiction and sector; the recipient; the legal source and the version read;
the trigger and the threshold; the time the trigger occurred and the facts for
it; the deadline as the legal owner computed it, and the calendar used; the
required content; the decision owner; status and receipt; the next update due;
any permitted exception or delay and its authority. Regimes start their clocks
at different events: awareness of a personal-data breach (GDPR and similar
data-protection laws), a determination that an incident is material (securities
disclosure), classification of a major or significant incident (some
financial-sector and network-and-information-security regimes), discovery of a
breach of unsecured health data, a contractual or insurance condition. Name a
clock with its trigger, never as a number of hours from "the incident".

This skill states no deadline and no applicability. Ask the legal or compliance
owner for the current text, whether it applies to this entity, and the number of
hours or days; write in the report that the examination did not verify them. If
no current legal source is available, record that verification gap at once.

Do not wait for the final forensic report when an initial notification may be due:
state what is known, what is under investigation, what was not examined and when
an update is expected.

**Report by question and phase.** Cover initial access, persistence and spread,
staging, possible exfiltration, recovery impairment, encryption, service impact,
containment and recovery. Phases can overlap, repeat or be absent. The earliest
observed artefact is not the start of the compromise, and encryption need not be
the adversary's last action. For each material conclusion give the source
references, the method and scope, what was observed and what inferred, the
confidence and its reason, the contrary evidence, the limitations and what would
change the answer. Use the outcomes the evidence supports: established, partial,
bounded negative, not determinable.

A negative exfiltration finding names the sources, systems, interval, coverage
gaps and the detection opportunity: whether the suspected transfer would have
appeared in that source. "Logs were present" is not a detection opportunity.

**Insurance and control findings.** Describe the control coverage, its
exceptions and the authentication route in use at the time. An exception on one
route does not show that the whole organisation lacked the control. Keep
technical findings apart from coverage decisions, and documented costs apart from
estimates.

**Sensitive output.** Keep the adversary's claims, ransom notes and victim
identifiers out of the body of the report. Cite where each is (note id, offset,
the sealed job output that holds it); an exhibit under access control holds a
value only where the operator asks for it by name. This skill authorises no contact
with the adversary, no payment, no negotiation and no external submission of case
material.

Never write a credential's value or its hash in the report, the ledger or the
board: that covers a key, token or password found in a note, an environment or a
store, and the hash of one. Write where it was, its type and length, what it
grants and the rotation it needs, and cite the sealed output. Jobs that extract
keys or credentials run with `secret_output: true`.

Include the response-action log: what was isolated, shut down, repaired, restored
or rebuilt, who authorised it, when, and what evidence that cost. State the
remaining access concerns and the restoration limits, with reasons.

**Does not show.** A report does not show that a duty was met, or applies; that
data left because it could have; or that access ended because the search stopped.
