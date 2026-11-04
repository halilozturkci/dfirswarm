# Skills in this pack

Fetch a body with `skill("<id>")`. A body may name others; fetch those the same way.

Router: `network/router`

- `analysis/engines-and-coverage` Zeek and Suricata analysis, and its coverage: A finding rests on what Zeek or Suricata produced, or on their silence.
- `beacons/periodicity` Testing a series of connections for periodicity: You suspect something calls home on a schedule, or a first pass found nothing.
- `capture/carve-from-images` Recovering packet records from disk or memory: No capture was supplied, but a memory image or disk image may retain packet buffers.
- `capture/derivatives` Making a working derivative of a capture: You need to filter, split, merge, deduplicate or build a capture from a hex dump.
- `capture/what-you-have` Assessing capture scope, integrity and time: You hold a pcap or pcapng and must say what it can show before any question about content.
- `correlate/host` Correlating network and host evidence: Network and host records may corroborate an endpoint, a process, a transfer or a time window.
- `evidence/captured-secrets` Authentication material in captures and logs: A capture, log or export may hold passwords, tokens, cookies, keys or key logs.
- `exfil/counters` What each byte counter measures: You are about to quote or compare a byte count from pcap_summary or Zeek.
- `exfil/volume` Assessing whether data left and how much: The question is whether data left the network, and how much.
- `flows/interpret` Flow records, exporter semantics and volume bounds: The evidence is NetFlow, IPFIX, sFlow or cloud flow-log records rather than packets.
- `logs/web-proxy-firewall` Working web, proxy and firewall logs: The evidence is line-oriented network logs rather than a packet capture.
- `metadata/dns-tls` DNS and encrypted-transport metadata: Traffic is mostly encrypted and you need to know which names and handshake fields stay observable.
- `metadata/encrypted-dns` Encrypted DNS, what is and is not recoverable: Resolver traffic may be DoH, DoT or DoQ, or a finding says "no DNS queries".
- `metadata/fingerprints` TLS fingerprints and Suricata output, with limits: A finding rests on a JA3 or JA4 value or a Suricata match.
- `network/router` Network notes by question: Pick a network note when none is listed, or you cannot choose.
- `sessions/objects` Exporting protocol objects with their provenance: You export files or other protocol objects from a capture with pcap_extract.
- `sessions/quic-http3` Reading QUIC and HTTP/3 in a capture: A capture holds QUIC or UDP port 443 traffic and you need what it shows, with or without secrets.
- `sessions/reconstruct` Reconstructing transactions and objects: You need what was actually sent, not just who spoke to whom.
- `sessions/tls-keylogs` Authorised TLS decryption from key logs: You hold approved TLS secrets and need to know which sessions of a capture they decrypt.
