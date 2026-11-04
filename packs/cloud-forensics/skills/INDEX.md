# Skills in this pack

Fetch a body with `skill("<id>")`. A body may name others; fetch those the same way.

Router: `cloud/router`

- `aws/cloudtrail` CloudTrail records, coverage and session origin: Supplied AWS CloudTrail exports need event interpretation or identity correlation.
- `aws/cloudtrail-integrity` CloudTrail integrity, cited from the operator's check: A CloudTrail integrity validation is wanted; none can be run here.
- `cloud/router` Cloud notes by question: Pick a cloud note when none is listed, or you cannot choose.
- `entra/directory-audit` Entra directory audit changes: Supplied Entra directory audit records must say who changed which identity, role, application or credential.
- `entra/signins` Entra sign-ins and their evidential limits: Supplied Entra sign-in exports need authentication, client, policy or account-activity analysis.
- `gcp/audit-logs` Cloud Audit Log entries: Supplied Cloud Audit Log entries must say which principal called which method on which resource.
- `google/workspace` Google Workspace exported audit evidence: Supplied Google Workspace logs concern account access, administration, OAuth grants, Drive or Gmail.
- `google/workspace-access` Workspace grants, delegation, sharing and forwarding: Reconstruct delegated access, Drive sharing or mail forwarding from Workspace evidence.
- `identity/grants` Consents, app credentials and mailbox rules as durable state: Consents, delegations, mailbox rules or account changes that can outlive a session.
- `identity/tokens` Tokens, grants and evidence of containment: Assessing whether account or application access could continue after a containment action.
- `kubernetes/audit` Kubernetes audit events and stages: Supplied API audit events must say which user did what to which object.
- `logs/exported-evidence` What an exported log file is: A cloud log export is the evidence and you must describe the file before reading its records.
- `logs/sources` Cloud source families to inventory: You must list which logs to expect or ask for in a cloud case.
- `logs/what-exists` What a cloud export covers, and what silence says: Cloud or SaaS logs are the evidence and an answer or a negative depends on their coverage.
- `m365/unified-audit-log` Microsoft 365 unified audit exports: Supplied Purview audit records need workload-specific interpretation and source-record correlation.
