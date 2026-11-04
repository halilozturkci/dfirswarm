---
id: sessions/quic-http3
title: Reading QUIC and HTTP/3 in a capture
when: A capture holds QUIC or UDP port 443 traffic and you need what it shows, with or without secrets.
needs: [evidence/captured-secrets]
tools: [quic_inspect]
requires_host: [tshark]
---

Use when a capture carries QUIC or HTTP/3. Not for TLS over TCP (`sessions/tls-keylogs`) or encrypted DNS (`metadata/encrypted-dns`).

1. **Which tshark.** `quic_inspect` records the `tshark` version and reads `tshark -G fields`: a build without the core QUIC fields is refused by name; a missing optional one is in `fields_missing` and each row's `limits` (`dissector_missing`).
2. **Rows and packets.** `datagrams` is one row per UDP datagram tshark dissected as QUIC; a datagram may coalesce several `packets`. `udp_443_not_dissected_as_quic` counts port 443 datagrams it did not read as QUIC.
3. **Initial metadata is not decryption.** `server_names` and `alpn` of a client Initial come from the Initial secrets, derived from the destination connection id: no key log. Handshake and application content need secrets (`keylog_file` as a FILE, never its text, or `use_embedded_secrets`); else `limits` says `encrypted_payload`. `frame_types` and `http3_stream_ids` appear only where tshark decoded the packet.
4. **A UDP tuple is not a session.** `attempts` come from connection ids. A Retry or Version Negotiation ends an attempt and the next Initial starts another (`ended_by`, `retry_scid`, `follows_attempt`); a changed endpoint inside one is `endpoints_changed`; a short-header packet whose id no long header named is an `unlinked` attempt.
5. **Absence.** No row means no datagram tshark dissected as QUIC, never a finding about the capture, never to be inferred from `ssl.log` or a TLS-only listing: `ssl.log` neither lists QUIC nor shows its absence (item 7).
6. **Sensitive.** `quic_inspect` is a `secret_output` tool: `all_results` holds connection ids and server names as they are. Run it as a job with `secret_output: true`.
7. **Zeek and Suricata.** Observed once, in this run, on synthetic traffic, not a real capture: Zeek 8.0.11, Suricata 7.0.10 (default config, no rules; JA3 setting not recorded). Zeek `quic.log`: `version` (`1`, `quicv2`, `unknown-<hex>`), `client_initial_dcid`, `client_scid`, `server_scid` (if a server Initial was read), `server_name`, `client_protocol` (first ALPN), `history`; a post-Retry Initial gave a second row; `ssl.log` had a row with version and cipher when both hellos decrypted, one without them for a client Initial alone, a Retry alone or an undecryptable server Initial, none for an undecryptable, truncated or reserved-version Initial; no token field, no Version Negotiation row. Suricata `eve.json` `quic`: `version` (`1`, `v2`, bare hex, `0` for Version Negotiation), `sni`, `ja3`, `ja3s`, `extensions`, no connection ids; no `ua`, `cyu`. An Initial that did not decrypt: Zeek a row with ids and `history` `I`, Suricata a `failed_decrypt` anomaly; a truncated one: neither. Not checked: real captures, other versions or configs, gQUIC, IPv6, arm64.

Shows: the QUIC datagrams one tshark build dissected, their headers, handshake metadata or frames where it decoded. Does not show: QUIC it did not dissect, content without secrets, a completed handshake. Its `fields_not_aligned` check covers id and version lists only. Record: hash, tshark version, `limits`, `ended_by`.
