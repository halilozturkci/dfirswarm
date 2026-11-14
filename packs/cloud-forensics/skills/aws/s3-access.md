---
id: aws/s3-access
title: S3 requests across access logs, data events and inventories
when: Supplied S3 access logs, data events or inventories must say who requested which object.
needs: [logs/what-exists]
card: cloud_normalise {"path": "<log object>", "provider": "aws_s3"}: access log, data events, inventory and configuration history are four sources: absent from one is not from all. A 2xx is not a transfer: compare bytes_sent with object_size. Does not show: a person, that an object left the bucket.
tools: [cloud_normalise, cloudtrail_parse]
requires_host: []
---

Use when you hold S3 server access logs, CloudTrail data events, inventories or the bucket's configuration history and must say which requester asked for which object, with what answer. Not for management events (`aws/cloudtrail`), VPC flow or GuardDuty. Offline: never authenticate to the account or list a bucket.

**Read the coverage `cloud_normalise` returns first.** It reads the server access log (`provider` `aws_s3`; an extension-less object by its path: a directory read skips it). `status` complete means every line became a row; others are in `rejected.jsonl`. `adapter_counts` counts `unknown_trailing_fields`. `cloudtrail_parse` reads data events; whether they were captured: `aws/cloudtrail`.

**Four sources, four claims.** The access log is requests the bucket received; a data event, an API call under the trail's selectors; an inventory, objects and versions as of its run; the configuration history (policy, ACLs, public-access block, logging) is state. A request absent from one is not absent from the others. A join on `bucket`, `key`, time and `principal` is a candidate.

**Attempted, successful, exposed and transferred are four claims.** `action` and `request_uri` name the request; `http_status` and `error_code` the answer; `outcome_basis` explains `outcome`. Public exposure is a separate claim, from the policy, ACL and public-access settings in force at the request, from the history; `authentication_type` and `principal` (`-` is null) say how a request was authenticated, not who was behind it. A transfer needs a successful answer with bytes: compare `bytes_sent` with `object_size` per request (`bytes_sent_note` explains a `-`). The record does not show what the requester did with it.

**Range, repeats, delay.** A ranged GET answers part of an object, so a 2xx is not the whole object. Count distinct `event_id` (request id) across overlapping exports. `time_raw` is the request time; delivery delay is not in the file (`logs/what-exists`): a file's last line does not end the activity.

**History of the configuration.** Changes to logging, policy and ACLs come from CloudTrail records of those calls (`notable` flags only policy, ACL and public-access-block writes; find logging calls such as PutBucketLogging with `events`) or from supplied snapshots (state at collection time). Whether logging or data events were on at the request comes from the history, never from a default.

**Does not show:** a person; that an object left the bucket; that the log holds every request; the configuration at a request, without a history.

**Sensitive output:** request URIs, keys, referers and user agents can hold secrets: run it as a job with `secret_output: true` (credential-named and -shaped values withheld; originals only with `write_values`; other secrets not recognised).
