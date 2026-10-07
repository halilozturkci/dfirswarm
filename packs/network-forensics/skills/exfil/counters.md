---
id: exfil/counters
title: What each byte counter measures
when: You are about to quote or compare a byte count from pcap_summary or Zeek.
needs: []
tools: [pcap_summary, zeek_run]
requires_host: []
---

Use when you quote a volume. Not for the question of whether data left (`exfil/volume`).

- `pcap_summary` `bytes_original` sums the original length each packet record declares: headers included, retransmissions and duplicates included. `bytes_captured` sums what was kept. Neither is unique application data or confirmed delivery, and a truncated packet makes them differ.
- Its rows are tuple aggregates: a tuple used again later merges with its earlier use, so a row is not one connection's volume. `top_talkers` counts an address as the SOURCE of a packet (what it sent, not what it received), both counters per address; `top_ports` counts destination ports in packets. A host or port filter applies to the rows and the top lists, not to the whole-capture totals.
- Zeek (`zeek_run`, `conn.log`) counts per connection as Zeek defines one: `orig_bytes` and `resp_bytes` are payload accounting by originator and responder, and the IP-byte fields mean something else. Read `conn_state`, missed bytes and `engine_diagnostics` before trusting a count, and note that a UDP flow, a connection with no handshake and a resumed one are all rows.
- The originator is the side that opened the connection, not the internal one.
- Encryption and compression add overhead and change size: wire volume neither equals nor bounds the source content.

Shows: a count under one stated definition. Does not show: application data delivered. Record: counter name, layer, direction, and why the two sides were assigned.
