---
id: capture/carve-from-images
title: Recovering packet records from disk or memory
when: No capture was supplied, but a memory image or disk image may retain packet buffers.
needs: [capture/what-you-have]
tools: [feature_scan, pcap_summary]
requires_host: [bulk_extractor, capinfos, tshark]
---

Use when no capture exists and an image may hold packet buffers. Not for a real capture file (`capture/what-you-have`), and never as proof that traffic did not happen.

1. Run the base pack's `feature_scan` with `only: ["net"]` as a scoped first pass, in a job with every output under `$OUT`. It runs `bulk_extractor`: record the version, the enabled scanners, the input representation and the exclusions, and do not assume it reads compressed or transformed content. A successful wrapper call does not show a complete scan: read its exit code, diagnostics and completion record, and qualify a partial result.
2. Keep every scanner output and `report.xml`. Its `packets.pcap`, when non-empty, is a **carved derivative**: hash it, run `capinfos`, then `pcap_summary`, and check structure with `tshark`.
3. A packet used in a finding needs its source byte range or forensic path and any transformation steps; a nearby feature-file offset is not that. Record where the mapping could not be made.
4. Timestamps: say whether each came from an intact capture record, was made up by the scanner, or is zero. Even an intact one needs corroboration before it orders anything. Check lengths, protocol structure, duplicates and the surrounding bytes.
5. A carved packet shows those bytes were in the source. It does not show the source machine sent them; keep false-positive, embedded-sample and duplicated-buffer explanations open until excluded.

Shows: bytes that look like packets, at offsets. Does not show: capture point, duration, completeness or absence. Record: image hash, scanner version and settings, output hashes, the source range per used packet.
Sensitive output: carved packets can hold credentials; keep them under `$OUT`, run the job with `secret_output: true`, and keep values out of summaries.
