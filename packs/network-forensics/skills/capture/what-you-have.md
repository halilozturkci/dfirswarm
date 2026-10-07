---
id: capture/what-you-have
title: Assessing capture scope, integrity and time
when: You hold a pcap or pcapng and must say what it can show before any question about content.
needs: [evidence/verify]
tools: [pcap_summary, zeek_run]
requires_host: [capinfos, zeek]
---

Use when you hold a pcap or pcapng and must say what it can show. Not for flow exports (identify the producer, sampling and byte-counter meaning first; no flow reader is bundled) or text logs (`logs/web-proxy-firewall`).

1. Hash the file. Run `pcap_summary` and a full `capinfos FILE`; keep both and reconcile their packet counts. `pcap_summary` is a census, not a session engine: read its interface table, drop counters, unsupported blocks and truncation counts.
2. **Snap length** limits bytes kept per packet; it does not say whether content survived. A 96-byte record can hold payload: minimal Ethernet, IPv4 and TCP headers take 54 bytes. Use the measured truncation (`truncation`, `payload_bytes_captured_total`) for the packets that matter; report what is recoverable, cut, or undetermined.
3. **Capture point** (inside, outside a NAT, a span port, the host) decides whether you see internal traffic, translated addresses and both directions.
4. **Clock.** Packet times are the sensor's; resolution, offset and accuracy are three different things. One matched event gives a local offset only. Estimate offset, drift and uncertainty from several independent matches across the window (NTP or clock-change records help); with none, keep original times and correlate over a stated interval.
5. **Gaps.** Record acquisition filters, interfaces, rotation and the segment list. A classic pcap has no drop counters, and a missing counter is not zero loss; a small file or quiet interval is not a gap. Keep acquisition loss, filtering, retention and unsupported decoding apart; deliberate removal needs its own corroboration.
6. Where the host has `zeek`, `zeek_run` adds per-protocol logs; read its `engine_diagnostics` first.

Only if you must filter, split, merge or build a capture: `capture/derivatives`. No capture: `capture/carve-from-images`.

Shows: what one sensor kept, from where, when by its own clock. Does not show: what the endpoints sent, that nothing was dropped, or that the clock was right.
Record: file hash, format, interfaces, snap lengths, counts, truncated packets, clock evidence, filters.
Sensitive output: a capture can hold credentials; run payload views as a job with `secret_output: true`; cite locators, never values.
