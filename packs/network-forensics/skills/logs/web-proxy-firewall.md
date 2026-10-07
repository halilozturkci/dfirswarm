---
id: logs/web-proxy-firewall
title: Working web, proxy and firewall logs
when: The evidence is line-oriented network logs rather than a packet capture.
needs: [capture/what-you-have]
tools: [network_log_summary, timestamp_decode]
requires_host: []
---

Use when the evidence is text logs. Not for a packet capture (`capture/what-you-have`) and not for a vendor format outside the three below.

1. Hash the source bytes, compressed files included. Record the producer, its configured log format, encoding, time zone, rotation and retention before you read a line.
2. Run `network_log_summary` as a job with outputs under `$OUT` and `secret_output: true`. It reads three grammars only: web (Apache or nginx common and combined), Squid native and upper-case KEY=VALUE firewall lines. Reconcile `lines`, `parsed`, `blank` and `unparsed`. The table is a convenience view, not a byte copy: every row carries its line number and byte offset, so check a material field against the source line, and treat a custom format, a decoding substitution (`decoding_substituted`) or a line over the limit as a stated limitation. Do not conclude from the returned aggregates alone.
3. **Fields.** Use the producer's schema. Response-body bytes are not connection bytes; a policy action is not a connection that was established or an application that succeeded; a label like ACCEPT or DROP means what the device's logging definition says. A forwarded-for header is untrusted unless the proxy trust chain is known. Keep original and translated (NAT) addresses and ports with direction and time; the generic parser does not resolve NAT.
4. **Time.** `timestamp_raw` is the text as written; `timestamp_utc` is filled only where the line gives enough (a web offset, Squid epoch seconds, an ISO prefix with a zone) and `timezone_source` says how. A syslog stamp has no year or zone: settle zone, year and daylight-saving ambiguity, and whether the time is start, completion or logging time, before you derive UTC (`timestamp_decode` converts a value you identified). Correlate within a stated uncertainty and use sensor and clock evidence.
5. Rotation gaps, a format change, clock jumps and unparsed lines are statements about the evidence. Investigate them; do not assume tampering.
6. **Sensitive output.** URLs, query strings, user-info and custom headers can carry credentials or session tokens. The table redacts targets by shape; a short secret in a path is not recognised. Keep raw material in sealed output, report the locator and the security implication, and never copy a credential, a credential-bearing URL or a hash of one into a finding or IOC list.

Shows: what the device logged, at the time it logged it. Does not show: who or what process sent a request, or that an action succeeded. A source address is an observed endpoint, not a person.
Record: source hash, producer and format, zone, counts, the lines a finding rests on.
