# Cloud and SaaS Forensics Pack

Logs that belong to somebody else's computer, examined as supplied exports: what
an export covers, and what the absence of a log actually means.

Depends on the Computer Forensics Base Pack.

## What it carries

**Nine skills**: `logs/what-exists` and `logs/sources` (what an export covers and which sources to
inventory), `m365/unified-audit-log`, `entra/signins`, `aws/cloudtrail`, `google/workspace` and
`google/workspace-access`, `identity/tokens` and `identity/grants`.

**Three tools**, all readers of exports that were supplied (nothing here connects to a tenant). `ual_parse` reads a
Microsoft 365 unified audit log export and opens the `AuditData` payload, keeping the whole of it beside the fields it
lifts out. `cloudtrail_parse` reads CloudTrail records and links each assumed-role session to the successful
AssumeRole calls in the records that could have issued it, as a candidate with its basis and never as attribution to a
person. `signin_analyse` reads an Entra or Google Workspace login export, keeps each record's ids, authentication
details and applied policies, and lists leads (a success that recorded one factor, failures shortly before a success, a
run of interrupted sign-ins before a success, an address seen once in the export, two successes whose coordinates imply a
high speed), each a hypothesis bounded by what the export holds; a sign-in the tool lists as interrupted (a listed-code heuristic) is a prompt, not a failure. Each says what it did not read, keeps every record with its file, record and line, withholds a value
named or shaped like a credential, and writes a whole result only under the run's output place.

**One goal template**: `tenant-compromise.md`.

## What this pack exists to stop

**Reporting that access stopped without proving it.** What a password reset, a session revocation or a removed
grant ends depends on the identity provider, the token type and the action taken. A consent is a separate grant and
a mailbox rule can keep acting with no interactive session. `identity/tokens` is the skill, and the goal template
asks for what the evidence shows about each containment action, or says it does not establish it.

**Reporting a quiet period as a finding.** Retention, licence, audit configuration and delivery delay vary by
service, tenant and event date, and a default you remember is not the tenant's setting. `logs/what-exists` makes
the examiner record what each export covers (the interval requested against the interval returned, who exported it,
with which query and permission, what failed) before any negative, and bounds every negative by it.

**Examining a tenant instead of its exports.** Everything here works from exports that were supplied. Nothing
authenticates to a tenant, replays a recovered token, or changes a configuration; a missing export is an
acquisition ask through the case workflow.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/cloud-forensics
    scripts/swarm.sh start --pack computer-forensics-base,cloud-forensics ...
