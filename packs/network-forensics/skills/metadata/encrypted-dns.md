---
id: metadata/encrypted-dns
title: Encrypted DNS, what is and is not recoverable
when: Resolver traffic may be DoH, DoT or DoQ, or a finding says "no DNS queries".
needs: []
card: "No DNS queries" is wrong when only port 53 was examined: list resolver endpoints and ports from pcap_summary {"path": "<capture>"} and zeek_run conn.log and ssl.log. DoT and DoQ use 853 by default, DoH is HTTPS on 443. Identifying the transport recovers no query: names come from resolver logs, the client's cache or authorised session secrets; say which supplied them. A resolver's SNI names the resolver, not what was asked. Settle the client's resolver configuration before reading absence. Does not show: the names asked or the user's intent.
tools: [pcap_summary, zeek_run]
requires_host: [tshark]
---

Use when DNS may be encrypted. Not for cleartext DNS or TLS handshake fields (`metadata/dns-tls`) or for fingerprints (`metadata/fingerprints`).

1. **Say what was examined.** "No DNS queries" is wrong when only port 53 was examined. List the resolver endpoints and ports in the capture from `pcap_summary` (a tuple row is a lead) and from `zeek_run`'s `conn.log` and `ssl.log`.
2. **Identify before you recover.** DoT is TLS on its own port (853 by default), DoQ is QUIC (853 over UDP by default), and DoH is HTTPS to a resolver on 443, like other web traffic. A name in the SNI or the certificate names the resolver; a shared resolver serves many users, so an address alone does not identify the service or the user. Identifying the transport recovers no query.
3. **Recovering queries needs an endpoint, not the wire:** resolver or forwarder logs, the client's own resolver or cache, or authorised session secrets for a session that a verified dissector (`tshark`, its version recorded) can then read. Say which one supplied the names.
4. **Signals that remain.** SVCB and HTTPS records in a cleartext lookup can advertise a service's `alpn` and its ECH keys; with ECH the inner name is hidden and the outer name is not the application host. A connection to a known resolver names the resolver, not what was asked. Sizes and timing are patterns, not names (`beacons/periodicity`).
5. A client's resolver setting, a refused encrypted attempt that falls back to port 53, or an application with its own resolver changes which path a name took: settle the client's configuration before reading absence.

Shows: that an encrypted resolver path existed, with whom, on which transport. Does not show: the names asked or the user's intent. Record: resolver endpoints and ports, how the transport was identified, what supplied any query.
Sensitive output: names can identify people; keep raw views in a job with `secret_output: true`.
