---
id: aws/s3-access
title: S3 requests across access logs, data events and inventories
when: Supplied S3 access logs, data events or inventories must say who requested which object.
needs: [logs/what-exists]
tools: [cloud_normalise, cloudtrail_parse]
requires_host: []
---

Use when you hold S3 server access logs, CloudTrail data events, object or version inventories or the bucket's configuration history and must say which requester asked for which object and how it was answered. Not for management events and sessions (`aws/cloudtrail`), VPC flow (`aws/vpc-flow`) or GuardDuty (`aws/guardduty`). Offline: supplied exports only; never authenticate to the account or list a bucket.

**Read the coverage `cloud_normalise` returns first.** It reads the server access log with `provider` `aws_s3`; a log object has no extension, so name it by path with `format` `s3log`. `status` is complete only if every line was read and became a row; a line that is not a record is in `rejected.jsonl`. `adapter_counts` counts `unknown_trailing_fields` (fields after the 27 the format lists, kept in the row). `cloudtrail_parse` reads data events; whether they were captured is the first question of `aws/cloudtrail`.

**Four sources, four claims.** The access log is requests the bucket received; a data event is an API call under the trail's selectors; an inventory lists objects and versions as of its own run; the configuration history (policy, ACLs, public-access block, logging) is state. A request absent from one is not absent from the others. A join on `bucket`, `key`, time and `principal` is a candidate to check row by row.

**Attempted, successful, exposed and transferred are four claims.** `action` and `request_uri` name the request; `http_status` and `error_code` say how it was answered, and `outcome_basis` says why `outcome` is what it is. Public exposure is a separate claim, from the policy, ACL and public-access settings in force at the request, taken from the history; `authentication_type` and `principal` (`-` is null) say how a request was authenticated, not who was behind it. A transfer needs a successful answer with bytes: compare `bytes_sent` with `object_size` per request (`bytes_sent_note` explains a `-`). Even then the record does not show what the requester did with it.

**Range, repeated and delayed.** A ranged GET answers part of an object, so a 2xx is not the whole object. Count distinct `event_id` (the request id) when exports overlap. `time_raw` is the request time; a log is delivered after its requests (`logs/what-exists`), so a file's last line does not end the activity.

**History of the configuration.** Changes to logging, policy and ACLs are read from CloudTrail records of those calls (`notable` flags them) or from supplied snapshots, which are state at their collection time. Whether logging or data events were on at the request comes from the history, never from a default.

**Does not show:** a person; that an object left the bucket; that the log holds every request; the configuration at the time of a request without a history.

**Sensitive output:** request URIs, keys, referers and user agents are in the rows and can hold secrets. Run the tool as a job with `secret_output: true`; it withholds credential-named and credential-shaped values and writes originals only with `write_values`. Other secrets are not recognised.
