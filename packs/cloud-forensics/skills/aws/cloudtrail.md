---
id: aws/cloudtrail
title: CloudTrail records, coverage and session origin
when: Supplied AWS CloudTrail exports need event interpretation or identity correlation.
needs: [logs/what-exists]
tools: [cloudtrail_parse]
requires_host: []
---

Use when you hold CloudTrail files, lookup-events pages or JSON Lines and must say which principal did what, from where, and what the export can show. Not for S3 access logs, VPC flow logs or GuardDuty findings (no reader here). Offline: never authenticate to the account.

**First, the surface.** Event History, trail files and event data store results differ in coverage and shape: establish account, region, event categories, selectors and interval. A missing `GetObject` record does not show nothing was read: check data events were captured. `cloudtrail_parse` reads Records files, arrays, JSON Lines, lookup-events pages and gzip; not tar or ZIP.

**Reconcile before any negative.** `status` is complete only if every record of every file was read. Read `coverage`, `file_census`, `rejected_records`, `pagination_markers` (a next page means one page of more), `digest_files` and `files_not_attempted_named`. Overlapping exports repeat events and every copy is kept: count distinct `event_id`, and cite it with the file, record and line.

**Fields that carry the case:** `userIdentity` (`accessKeyId`, `sourceIdentity`, `sessionContext`), `errorCode`, `requestParameters`, `responseElements`, `additionalEventData` (console `MFAUsed`), `recipientAccountId`, `sharedEventID`. The tool keeps them; `outcome` says whether an error was recorded, not whether a change took effect.

**Sessions.** An `AssumedRole` identity names a session, not a person. `session_origin` is a candidate: the successful AssumeRole-family call matching this session's access key id or ARN, with its `basis` and source event. `unresolved` lists the matches (to a cap) and picks none; `not_found`: no call fits (another key or a creationDate miss is listed, not chosen). A failed call is never a source. A chained caller has its own `session_origin`; a person needs identity-provider evidence and corroboration beyond these logs.

**Errors.** `error_class` is by the code's name. Repeated authorisation denials are a lead: check identity, resources, timing, earlier successes and known automation. Throttling, validation and service errors are not denials.

**Flagged calls** (`notable`) name an API, not an effect: credential, identity, policy, ACL, snapshot-sharing and logging calls. Read the result, request and effective configuration before saying what changed. `StopLogging` suspends that trail's recording and delivery; it deletes no delivered record and stops no other trail or source: correlate trail scope, selectors, delivery, other trails and the inventory; an observed gap is not proof the call caused it.

**Integrity.** The tool validates no digest file or chain, and a file hash is not that validation: unless the case supplies a validation record, say it was not performed.

**Does not show:** a person; that a call took effect; what was not logged; a complete export.

**Sensitive output:** request and response fields can hold secrets. Run the tool as a job with `secret_output: true`; it withholds credential-named and credential-shaped values and writes originals only with `write_values`. Report an access key id in full, a secret never.
