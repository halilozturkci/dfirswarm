---
id: capture/carve-from-images
title: Recovering packet records from disk or memory
when: No capture was supplied, but a memory image or disk image may retain packet buffers.
needs: [capture/what-you-have]
tools: [feature_scan, pcap_summary]
requires_host: [bulk_extractor, capinfos, tshark]
---

Use the base pack's `feature_scan` with `only: ["net"]` against a verified
working copy or the read-only evidence path. The net scanner ignores the file
system and searches raw bytes for packet records and network features. Its
`packets.pcap`, when non-empty, is a **carved derivative**, not an original
capture.

Record the source image hash, scanner version and command. Hash
`packets.pcap`, run `capinfos`, then run `pcap_summary`. Keep `ip.txt`,
`tcp.txt`, `ether.txt`, the complete pcap and `report.xml`; the byte offsets in
the feature files are the provenance back to the source image.

Carved packets usually have zero timestamps, duplicate frames and no capture
point or dropped-packet counters. Never infer chronology, capture duration or
absence from them. Validate protocol structure with `tshark`, and treat a
packet as a lead until its source offset and surrounding bytes are checked.

Do not scan a live malware sample on the host. Disk and memory samples stay in
the worker VM, mounted read-only, and every derivative goes under `work/`.
