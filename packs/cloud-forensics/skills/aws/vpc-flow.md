---
id: aws/vpc-flow
title: VPC Flow Logs, layout and what a record covers
when: Supplied VPC Flow Log files must say which interface saw which traffic, in which window.
needs: [logs/what-exists]
card: cloud_normalise {"path": "<flow log>", "provider": "aws_vpc"}: check fields_from; a headerless file not in v2 order needs {"format": "vpcflow", "vpc_flow_fields": "<names>"}. A record is a window, not a connection. NODATA and SKIPDATA rows carry no counts: not a flow of zero, not quiet. Does not show: a connection, application success, content, the person at an address.
tools: [cloud_normalise]
mentions: [network_log_summary]
requires_host: []
---

Use when you hold VPC Flow Log files and must say which interface saw which traffic between which addresses, when. Not for packets, other flow formats (see below) or what an application did. Offline: never authenticate to the account.

**Read the coverage `cloud_normalise` returns first.** It knows the file by its first line (`provider` `aws_vpc`). `fields_from` says how the field order was known: a header line (a later one replaces it), the 14-field version 2 default, or `vpc_flow_fields`; a record with no known order is in `rejected.jsonl`. `status` complete means every record was read.

**Version and layout.** `flow_log_version` is the version field and `flow_log_version_from_fields` the highest version among the field names; a note says when they differ. A field a custom format left out is absent, not zero. `fields` holds every field as written (`-` is null); `unknown_field_names` the names the AWS page does not list.

**Scope.** `tenant` is the account of the source interface and `resource` its interface id. `source_ip` and `destination_ip` are `srcaddr` and `dstaddr`; `pkt-srcaddr`, `pkt-dstaddr`, `vpc-id`, `subnet-id` and `instance-id`, where present, are in `fields`. Which instance, NAT device or interface owns an address comes from a supplied inventory for that time, not the log.

**A record is a window.** `time_raw` and `end_time_raw` bound the interval aggregated; `packets` and `bytes` count it. A record is not a connection; one flow can fill several. Take the interval length from supplied settings.

**`NODATA` and `SKIPDATA`.** `row_kind` is `no_flow_record` when `log_status` is NODATA (no traffic in the interval, per the AWS page) or SKIPDATA (records skipped in it). No count is lifted; `adapter_counts` has `log_status_NODATA` and `log_status_SKIPDATA`. NODATA is not a flow of zero; an interval beside a SKIPDATA record is not shown to be quiet.

**Accepted is not application success.** `action` ACCEPT gives `outcome` `success` and REJECT `failure`, the log's word for the traffic; `outcome_basis` says ACCEPT does not show a connection was established, nor that a service answered. Bytes count traffic in a window, not the size of what was taken.

**Other flow records.** The general meaning of flow records (exporter, sampling, timeouts, counters) is the network pack's `flows/interpret` if the network pack is loaded; check the run's tool inventory. `network_log_summary` does not read this schema.

**Does not show:** application success; content; the person or process behind an address; that the log holds every flow.

**Sensitive output:** addresses are personal data and tag fields free text: run it as a job with `secret_output: true` (credential-named and -shaped values withheld).
