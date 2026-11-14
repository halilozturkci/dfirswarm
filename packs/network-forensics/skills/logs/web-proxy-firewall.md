---
id: logs/web-proxy-firewall
title: Working web, proxy and firewall logs
when: The evidence is line-oriented network logs rather than a packet capture.
needs: [evidence/captured-secrets]
card: network_log_summary {"path": "<log>"} as a job with secret_output: true. Reconcile lines, parsed, blank and unparsed; check a material field against its line. Does not show: who sent a request, or that an action succeeded.
tools: [network_log_summary, timestamp_decode]
requires_host: []
---

Use when the evidence is text logs. Not for a packet capture (`capture/what-you-have`) or a vendor format outside the three below.

1. Hash the source bytes (compressed files too). Before reading a line, record the producer, its log format, encoding, zone, rotation and retention.
2. Run `network_log_summary` as a job, outputs under `$OUT`, `secret_output: true`. It reads web (Apache or nginx common and combined, referer a column), Squid native and upper-case KEY=VALUE firewall lines. Reconcile `lines`, `parsed`, `blank` and `unparsed`. The table is a view, not a byte copy: each row carries line number and byte offset, so check a material field against the source line; a custom format, `decoding_substituted` or an over-limit line is a limitation. Do not conclude from aggregates alone.
3. **Fields.** Use the producer's schema. Response-body bytes are not connection bytes; a policy action is not an established connection or a successful application; ACCEPT or DROP means what the device's logging definition says. A forwarded-for header is untrusted unless the proxy trust chain is known. Keep original and translated (NAT) addresses and ports with direction and time; the parser does not resolve NAT.
4. **Time.** `timestamp_raw` is as written; `timestamp_utc` is filled only where the line gives enough (a web offset, Squid epoch seconds, a zoned ISO prefix), `timezone_source` saying how. A syslog stamp has no year or zone: settle zone, year, daylight saving and whether it is start, completion or logging time before deriving UTC (`timestamp_decode` converts a value you identified). Correlate within a stated uncertainty, using sensor and clock evidence.
5. Rotation gaps, a format change, clock jumps and unparsed lines are statements about the evidence: investigate, do not assume tampering.
6. **Sensitive output.** URLs, query strings, user-info and custom headers can carry credentials or tokens. The table redacts by shape, per column: target and referer lose user-info, token-shaped path text and query values; an address column is an IP address or takes the same rule, as does every other text column; text after a grammar's last field is in `unparsed_tail` (`parse_status` partial). A hash-, GUID- or UUID-shaped path part is withheld though no secret, and so are the query and fragment of a target or referer over 64 KiB, parameter names too (`write_values` in a job returns the originals); a short secret in a path is not recognised. Keep raw material sealed, report the locator and security implication, and never copy a credential, a URL bearing one, or its hash into a finding or IOC list.

Shows: what the device logged, at the time it logged it. Does not show: who or what process sent a request, or that an action succeeded. A source address is an observed endpoint, not a person.
Record: source hash, producer and format, zone, counts, the lines a finding rests on.
