---
id: aws/vpc-flow
title: VPC Flow Logs, layout and what a record covers
when: Supplied VPC Flow Log files must say which interface saw which traffic, in which window.
needs: [logs/what-exists]
tools: [cloud_normalise]
mentions: [network_log_summary]
requires_host: []
---

Use when you hold VPC Flow Log files and must say which interface saw which traffic between which addresses in which window. Not for packets, other flow formats (see below) or what an application did. Offline: supplied files only; never authenticate to the account.

**Read the coverage `cloud_normalise` returns first.** It recognises the file from its first line (`provider` `aws_vpc`). `fields_from` says how the field order was known: the file's header line (a later one replaces it, as in files put end to end), the 14-field version 2 default order, or `vpc_flow_fields`; a record with no known order is in `rejected.jsonl`. `status` is complete only if every record was read.

**Version and layout.** `flow_log_version` is the version field and `flow_log_version_from_fields` the highest version among the field names; a note says when they differ. A custom format holds only the fields it chose, so a missing field is absent, not zero. `fields` holds every field as written (`-` is null); `unknown_field_names` the names the AWS page does not list.

**Scope.** `tenant` is the account of the source interface and `resource` its interface id. `source_ip` and `destination_ip` are `srcaddr` and `dstaddr`; where the format has them, `pkt-srcaddr`, `pkt-dstaddr`, `vpc-id`, `subnet-id` and `instance-id` are separate fields in `fields`. Which instance, NAT device or interface an address belongs to comes from a supplied inventory for that time, not from the log.

**A record is a window.** `time_raw` and `end_time_raw` bound the interval aggregated into the record; `packets` and `bytes` count that interval. A record is not a connection, and one flow can fill several records. The interval length is a setting of the log: take it from supplied settings.

**`NODATA` and `SKIPDATA`.** `row_kind` is `no_flow_record` when `log_status` is NODATA (no traffic in the interval, as the AWS page says) or SKIPDATA (some records were skipped in the interval). No packet or byte count is lifted and `adapter_counts` has `log_status_NODATA` and `log_status_SKIPDATA`. NODATA is not a flow of zero, and an interval beside a SKIPDATA record is not shown to be quiet.

**Accepted is not application success.** `action` ACCEPT gives `outcome` `success` and REJECT `failure`: the log's word for the traffic; `outcome_basis` says ACCEPT does not show a connection was established. Nothing here shows a service answered or what the application did. Bytes count traffic in a window, not the size of what was taken or what it held.

**Other flow records.** The general meaning of flow records (exporter, sampling, timeouts, counters) is the network pack's `flows/interpret` if the network pack is loaded; check the run's tool inventory. `network_log_summary` does not read this schema.

**Does not show:** application success; content; the person or process behind an address; that the log holds every flow.

**Sensitive output:** addresses are personal data and tag fields can hold free text. Run the tool as a job with `secret_output: true`; it withholds credential-named and credential-shaped values.
