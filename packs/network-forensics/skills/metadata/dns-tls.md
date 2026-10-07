---
id: metadata/dns-tls
title: DNS and encrypted-transport metadata
when: Traffic is mostly encrypted and you need to know which names and handshake fields stay observable.
needs: [capture/what-you-have]
tools: [pcap_summary, zeek_run]
requires_host: [zeek, tshark]
---

Use when payload is encrypted and you need what metadata still shows. Not for JA3/JA4 and Suricata fields (`metadata/fingerprints`) or for recovering content (`sessions/reconstruct`).

First say what is observable here: cleartext DNS, an exposed handshake, encrypted-transport metadata, or content recovered with supplied secrets. `pcap_summary` shows which endpoints and ports to look at; `zeek_run` (it runs `zeek`) gives `dns.log` and `ssl.log`, and `tshark` reads fields the logs lack.

**DNS.** Separate client-to-resolver from resolver-to-authority traffic: an observed source may be a resolver. Keep query and response paired, with type, response code, answers, CNAME chain, TTL and retries. A query does not show a connection, a successful resolution or a user action. Long labels, TXT volume, one repeating subdomain pattern and NXDOMAIN bursts are leads: discovery, filtering, telemetry and misconfiguration look alike. A name is worth more than an address (addresses are shared and rotate).

**TLS handshake.** In TLS 1.2 the Certificate message is separate from ServerHello and usually visible in a full handshake. In TLS 1.3 everything after ServerHello, the Certificate included, is encrypted, and a resumed session may send none. An exposed ClientHello shows offered versions, ciphers, extensions and SNI. ECH can hide the inner name, and an outer name is not the application host. A self-signed, mismatched or short-lived certificate is a lead: judge it with the deployment's trust history.

**Encrypted DNS and QUIC.** DoH, DoT and DoQ hide the names: a connection to a resolver shows the resolver, not what was asked. "No DNS queries" is wrong when only port 53 was examined. QUIC carries its TLS 1.3 handshake in its own frames; some handshake metadata may be visible in Initial packets, later content needs secrets, and HTTP/3 needs HTTP/3-aware reading. Absence from `ssl.log` is not absence of encrypted traffic. This pack has no QUIC or encrypted-DNS method yet: state the limit. Only if you rely on a JA3 or JA4 value or Suricata output: `metadata/fingerprints`.

**Sizes and timing** show repeated exchanges without content: a pattern, never proof of command and control (`beacons/periodicity`).

Shows: what the wire exposed under this TLS version and DNS path. Does not show: content, the user's intent, or the application host. Record: engine versions, what was exposed, what only inference supports.
Sensitive output: names and SNI can identify people; keep raw views in a job with `secret_output: true`.
