---
id: logs/web-proxy-firewall
title: Working web, proxy and firewall logs
when: The evidence is line-oriented network logs rather than a packet capture.
needs: [capture/what-you-have]
tools: [network_log_summary, timestamp_decode]
requires_host: []
---

Hash the source and identify the producer, format, time zone, rotation policy
and retention window before interpreting a line. Run `network_log_summary` to
write a complete normalised TSV and its parse-error file under `work/`; do not
base a conclusion on only the returned aggregate.

For web access logs, pivot on client, method, status, bytes, user agent and
request target. Separate application responses from reverse-proxy responses,
and remember that an upstream may rewrite the client address. For Squid-style
proxy logs, keep the result/status pair, hierarchy code and MIME type. For
firewall key/value logs, distinguish `ACCEPT` from `DROP`, interface direction,
NAT addresses and TCP flags.

Normalise time only after identifying its zone. Preserve the original timestamp
and raw line beside every normalised row. Rotation gaps, a sudden format change,
clock jumps and lines the parser could not read are findings about evidence
quality; they are not silently discarded.

Correlate a request or connection with host evidence by an explicit clock
offset. A source address in a proxy or NAT log identifies an observed network
endpoint, not automatically a person or process.
