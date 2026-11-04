---
id: m365/mailbox-persistence
title: Mailbox persistence, from configuration to delivery
when: Inbox rules, forwarding, delegates or permissions must be traced from change to mail.
needs: [logs/what-exists]
tools: [ual_parse, cloud_normalise]
requires_host: []
---

Use when evidence concerns inbox rules, forwarding, delegates, recipient permissions, transport controls or application grants on mailboxes and you must say what was set, who set it and whether mail was affected. Not for sign-ins (`entra/signins`) or token revocation (`identity/tokens`). Offline: supplied exports only; never authenticate to the tenant.

**Four steps, four claims.** Configuration is not effective authorisation, which is not execution, which is not delivery. Place each finding at the step its evidence reaches and say what the next step would need.

1. **Configuration.** A supplied snapshot of rules, forwarding settings, delegates, permissions or transport controls is state at its collection time. `m365/unified-audit-log` says there is no reader here for mailbox configuration or message delivery: read a snapshot in a recorded job and say so. It shows what existed then, not who set it or when.
2. **Authorisation change.** `ual_parse` reads the audit records of the changes: filter `operations` by exact name (`notable_only` keeps rule, forwarding, permission, consent and role ones) and read `audit_data` for the actor, the target mailbox and the parameters. A record is a recorded change with its `Id`, not that the setting is still in force or took effect (`m365/unified-audit-log`).
3. **Execution.** Whether a rule or control acted needs its conditions, its enabled state and evidence of mail it processed. `MailItemsAccessed` records access to items, not a rule firing. A rule that exists is a lead, not an act.
4. **Delivery.** Message trace, the recipient's mailbox or the destination's logs show a message reaching a place. No reader for message trace is here: correlate supplied trace rows by sender, recipient, message id and time as written, in a recorded job, and say so.

**Application grants** are directory-side changes: `cloud_normalise` reads Entra directory audit rows (`targets`, `modified_properties`, `change_topics`; `entra/directory-audit`) and Workspace activities (`before_after`, `topic_hints`; `google/workspace-access`). Grant, consent and use are separate (`identity/grants`).

**Transport controls** act on mail in flight with no mailbox rule, so a mailbox with no rule is not shown to have no forwarding. Look for changes to them in the audit records and in a snapshot of the tenant's controls.

**Does not show:** that a rule acted or a message was delivered; a person; the state after the last supplied record; what the audit configuration did not capture.

**Sensitive output:** parameters and properties can hold secrets and addresses are personal data. Run `ual_parse` as a job with `secret_output: true`; it withholds credential-named and credential-shaped values and writes originals to `ual-values.jsonl` only with `write_values`.
