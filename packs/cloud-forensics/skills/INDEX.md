# Skills in this pack

Fetch a body with `skill("<id>")`. A body may name others; fetch those the same way.

- `aws/cloudtrail` CloudTrail records, coverage and session origin: Supplied AWS CloudTrail exports need event interpretation or identity correlation.
- `entra/signins` Entra sign-ins and their evidential limits: Supplied Entra sign-in exports need authentication, client, policy or account-activity analysis.
- `google/workspace` Google Workspace exported audit evidence: Supplied Google Workspace logs concern account access, administration, OAuth grants, Drive or Gmail.
- `google/workspace-access` Workspace grants, delegation, sharing and forwarding: You must reconstruct delegated access, Drive sharing or mailbox forwarding from Workspace evidence.
- `identity/grants` Consents, application credentials and mailbox rules as durable state: Evidence holds application consents, delegations, mailbox rules or account changes that can outlive a session.
- `identity/tokens` Tokens, grants and evidence of containment: Assessing whether account or application access could continue after a containment action.
- `logs/sources` Cloud source families to inventory: You must list which logs to expect or ask for in a cloud case.
- `logs/what-exists` What a cloud export covers, and what silence can say: Supplied cloud or SaaS logs are the evidence, and an answer or a negative depends on what they hold.
- `m365/unified-audit-log` Microsoft 365 unified audit exports: Supplied Purview audit records need workload-specific interpretation and source-record correlation.
