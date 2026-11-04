---
id: sessions/quic-http3
title: Reading QUIC and HTTP/3 in a capture
when: A capture holds QUIC or UDP port 443 traffic and you need what it shows, with or without secrets.
needs: [evidence/captured-secrets]
tools: [quic_inspect]
requires_host: [tshark]
---

Use when a capture carries QUIC or HTTP/3: versions, connection ids, handshake metadata, streams. Not for TLS over TCP (`sessions/tls-keylogs`) or encrypted DNS (`metadata/encrypted-dns`).

1. **Which tshark.** `quic_inspect` records `tshark` (its version) and reads `tshark -G fields`: a build without the core QUIC fields is refused by name, and a missing optional one is in `fields_missing` and in the `limits` of every row as `dissector_missing`. QUIC support differs between builds, so record the version. This pack shows nothing about what Zeek or Suricata write for QUIC: do not cite either for it.
2. **Rows and packets.** `datagrams` is one row per UDP datagram tshark dissected as QUIC, in capture order; a datagram may coalesce several `packets` (`header` long or short, `type`, `version`, `dcid`, `scid`, `token`). `udp_443_not_dissected_as_quic` counts port 443 datagrams it did not read as QUIC (another version, or no dissector): they are neither QUIC nor not QUIC.
3. **Initial metadata is not decryption.** `server_names` and `alpn` of a client Initial come from the Initial secrets, which derive from the destination connection id and need no key log. Handshake and application content need secrets (`keylog_file` as a FILE, never its text, or `use_embedded_secrets`); without them a row says `encrypted_payload` in `limits`. `frame_types` and `http3_stream_ids` appear only where tshark decoded the packet. Map an HTTP/3 object to its stream id, not to the connection; QPACK headers depend on state built across streams, so a lost packet can leave later headers unreadable.
4. **A UDP tuple is not a session.** `attempts` are built from connection ids. A Retry or a Version Negotiation packet ends an attempt and the next Initial starts another (`ended_by`, `retry_scid`, `follows_attempt`); a change of endpoint inside one is `endpoints_changed` (migration or a NAT rebinding, not a second connection); a short-header packet whose id no long header named is an `unlinked` attempt, perhaps the same connection under an id issued after the handshake. An attempt is not a completed handshake.
5. **Absence.** No row means no datagram tshark dissected as QUIC, never a finding about the capture, and never to be inferred from `ssl.log` or a TLS-only listing, which hold no QUIC.
6. **Sensitive.** `quic_inspect` is a `secret_output` tool: connection ids and server names are in the whole table (`all_results`) as they are. Run it as a job with `secret_output: true`.

Shows: the QUIC datagrams one tshark build dissected, their headers, and handshake metadata or frames where it decoded them. Does not show: QUIC it did not dissect, content without secrets, or that a connection completed. Record: capture hash, tshark version, `limits` seen, attempts relied on with their `ended_by`, the secrets' source by counts only.
