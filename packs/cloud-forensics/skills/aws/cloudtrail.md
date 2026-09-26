---
id: aws/cloudtrail
title: CloudTrail, and the events that are not in it
when: The tenant is AWS.
needs: [logs/what-exists]
tools: [cloudtrail_parse]
requires_host: [aws]
---

CloudTrail records API calls as JSON, gzipped, one file per batch, delivered to
a bucket. `cloudtrail_parse` reads a file, a directory or a gzipped archive of
them and normalises the records.

**Management events are on by default; data events are not.** So
`CreateBucket` is recorded and `GetObject` usually is not, which means "was the
data read" is frequently unanswerable unless somebody turned data events on
beforehand. Establish that first and say so.

The fields that carry the case:

    eventTime, eventName, eventSource     what happened
    userIdentity                          who: type, arn, userName, and for an
                                          assumed role the sessionContext with
                                          the role and when it was assumed
    sourceIPAddress                       where from, or an AWS service name
    userAgent                             the SDK, the CLI, or a browser
    errorCode                             a refusal, which is often the loudest signal
    requestParameters, responseElements   the detail

**`AccessDenied` in volume is the shape of enumeration.** An identity trying a
hundred calls and being refused ninety of them is mapping its own permissions,
and that is usually the first hour of an intrusion.

**An assumed role hides the human.** `userIdentity.type` of `AssumedRole` names
the session, not the person; the `sessionIssuer` and the earlier
`AssumeRole` call are what connect it back to an account or a federated
identity. `cloudtrail_parse` emits `role_assumed_by` only when it finds a
matching role ARN and session name in the supplied records; absence of that
field means the acquisition did not establish the human. Follow that chain
before you attribute anything.

The calls worth alerting on: `ConsoleLogin` without multi-factor,
`CreateAccessKey` and `CreateUser`, `AttachUserPolicy` with an administrator
policy, `PutBucketPolicy` and `PutBucketAcl` making something public,
`ModifySnapshotAttribute` sharing a volume with another account,
`DeleteTrail` and `StopLogging`, and `GetSecretValue` in volume.

**`StopLogging` is the equivalent of clearing the event log.** It is recorded —
the stop itself is a management event — and the gap that follows is the finding.
