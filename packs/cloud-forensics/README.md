# Cloud and SaaS Forensics Pack

Logs that belong to somebody else's computer: what each provider keeps, for how
long, and what the absence of a log actually means.

Depends on the Computer Forensics Base Pack.

## What it carries

**Six skills**: `logs/what-exists`, `m365/unified-audit-log`, `entra/signins`,
`aws/cloudtrail`, `google/workspace`, `identity/tokens`.

**Three tools.** `ual_parse` reads a Microsoft 365 unified audit log export and
explodes the `AuditData` column — which is JSON, is where almost everything
lives, and is an unreadable blob in a spreadsheet. `cloudtrail_parse` reads
CloudTrail, resolves an assumed role back to the session that issued it, and
counts the refusals that are the shape of permission enumeration.
`signin_analyse` surfaces a success that satisfied one factor on a tenant that
requires two, failure bursts before a success, addresses an account has never
used, and pairs whose implied travel speed is impossible — with the speed
computed, so the claim is measurable rather than asserted.

**One goal template**: `tenant-compromise.md`.

## What this pack exists to stop

**Reporting that access stopped without proving it.** Refresh-token behaviour
depends on the identity provider, token type, and revocation action. OAuth
consent is a separate grant and must be reviewed and revoked explicitly; a
mailbox rule can keep acting with no interactive session. `identity/tokens` is
the skill, and the goal template will not pass its checks without evidence of
the relevant revocation action.

**Reporting a retention gap as a finding.** Defaults vary by service, licence,
event date, and tenant policy. For example, current Purview Audit (Standard)
defaults to 180 days for records generated since 17 October 2023, Entra keeps
sign-ins for 7 days on Free and 30 days on P1/P2, and CloudTrail Event History
keeps 90 days of regional management events. Record the tenant's effective
settings and export time before interpreting a quiet period.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/cloud-forensics
    scripts/swarm.sh start --pack computer-forensics-base,cloud-forensics ...
