---
id: cloud/router
title: Cloud notes by question
when: Pick a cloud note when none is listed, or you cannot choose.
router: true
needs: []
tools: []
requires_host: []
---

Use when the index shows only this line and you need a cloud note. Not for rules: each note holds its own.

Any cloud export
`logs/what-exists` coverage, what silence says
`logs/sources` log families to inventory or ask for
`logs/exported-evidence` what the file is, before what it says

Microsoft
`m365/unified-audit-log` Purview audit records
`entra/signins` who authenticated, how, from where
`entra/directory-audit` who changed identities and applications

Other providers
`aws/cloudtrail` principal, action, origin
`aws/cloudtrail-integrity` operator's digest check, cited
`google/workspace` Workspace audit exports
`google/workspace-access` delegation, sharing, forwarding
`gcp/audit-logs` Cloud Audit Log entries
`kubernetes/audit` API server audit events

The account behind the logs
`identity/grants` consents, app credentials, mailbox rules
`identity/tokens` access after containment
