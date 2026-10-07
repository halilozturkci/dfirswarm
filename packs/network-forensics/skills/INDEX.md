# Skills in this pack

Fetch a body with `skill("<id>")`. A body may name others; fetch those the same way.

- `beacons/periodicity` Testing a series of connections for periodicity: You suspect something calls home on a schedule, or a first pass found nothing.
- `capture/carve-from-images` Recovering packet records from disk or memory: No capture was supplied, but a memory image or disk image may retain packet buffers.
- `capture/derivatives` Making a working derivative of a capture: You need to filter, split, merge, deduplicate or build a capture from a hex dump.
- `capture/what-you-have` Assessing capture scope, integrity and time: You hold a pcap or pcapng and must say what it can show before any question about content.
- `correlate/host` Correlating network and host evidence: Network and host records may corroborate an endpoint, a process, a transfer or a time window.
- `exfil/counters` What each byte counter measures: You are about to quote or compare a byte count from pcap_summary or Zeek.
- `exfil/volume` Assessing whether data left and how much: The question is whether data left the network, and how much.
- `logs/web-proxy-firewall` Working web, proxy and firewall logs: The evidence is line-oriented network logs rather than a packet capture.
- `metadata/dns-tls` DNS and encrypted-transport metadata: Traffic is mostly encrypted and you need to know which names and handshake fields stay observable.
- `metadata/fingerprints` TLS fingerprints and Suricata output, with limits: A finding rests on a JA3 or JA4 value or a Suricata match.
- `sessions/objects` Exporting protocol objects with their provenance: You export files or other protocol objects from a capture with pcap_extract.
- `sessions/reconstruct` Reconstructing transactions and objects: You need what was actually sent, not just who spoke to whom.
