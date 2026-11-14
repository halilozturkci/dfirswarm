---
id: aws/cloudtrail
title: CloudTrail records, coverage and session origin
when: Supplied AWS CloudTrail exports need event interpretation or identity correlation.
needs: [logs/what-exists]
card: cloudtrail_parse {"path": "<CloudTrail files>"}: read status, coverage and pagination_markers first: complete means every record was read, not that the account logged everything. Count distinct event_id. outcome is an error recorded, not an effect; notable names an API. session_origin is a candidate (unresolved picks none), never a person. No digest is validated. Does not show: a person, an effect, unlogged calls.
tools: [cloudtrail_parse]
mentions: [guardduty_findings]
requires_host: []
---

Use when you hold CloudTrail files or lookup-events pages and must say which principal did what, from where. Not for S3 or VPC logs, or GuardDuty (`guardduty_findings`). Offline: never authenticate to the account.

**The surface.** Event History, trail files and event data stores differ in coverage and shape: establish account, region, event categories, selectors and interval. No `GetObject` record does not show no read: check data events were captured. `cloudtrail_parse` reads Records files, arrays, JSON Lines, lookup-events pages and gzip; not tar or ZIP.

**Reconcile before any negative.** `status` complete means every record of every file was read; read `coverage`, `file_census`, `rejected_records`, `pagination_markers` (a next page: one page of more), `digest_files` and `files_not_attempted_named`. Overlapping exports repeat events: count distinct `event_id`; cite file, record, line.

**Fields that carry the case:** `userIdentity` (`accessKeyId`, `sourceIdentity`, `sessionContext`), `errorCode`, `requestParameters`, `responseElements`, `additionalEventData` (console `MFAUsed`), `recipientAccountId`, `sharedEventID`. `outcome` is whether an error was recorded, not an effect. `error_class` is by the code's name; only authorisation denials are refusals; repeated ones are a lead (check identity, resources, timing, earlier successes, automation).

**Sessions.** An `AssumedRole` identity names a session, not a person. `session_origin` is a candidate: the successful AssumeRole-family call matching the session's access key id or ARN, with its `basis`. `unresolved` lists matches (to a cap) and picks none; `not_found`: none fits (another key or a creationDate miss is listed, not chosen). A failed call is never a source. A chained caller has its own `session_origin`; a person needs identity-provider evidence.

**Flagged calls** (`notable`: credential, identity, policy, ACL, snapshot-sharing, logging) name an API, not an effect: read result, request and configuration first. `StopLogging` suspends that trail's recording and delivery: it deletes nothing delivered, stops no other trail; a gap is not proof it caused it: correlate scope, selectors, other trails.

**Integrity.** No digest file or chain is validated (a file hash is not that): with no supplied record, say none was; only if one is wanted, `aws/cloudtrail-integrity`.

**Does not show:** a person; that a call took effect; what was not logged; a complete export.

**Sensitive output:** request and response fields can hold secrets: run it as a job with `secret_output: true` (credential-named and -shaped values withheld; originals only with `write_values`). Report an access key id in full, a secret never.
