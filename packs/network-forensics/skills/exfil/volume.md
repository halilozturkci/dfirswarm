---
id: exfil/volume
title: Assessing whether data left and how much
when: The question is whether data left the network, and how much.
needs: [capture/what-you-have]
tools: [pcap_summary, zeek_run]
requires_host: []
---

Use when the question is data leaving. Not for detection: volume and destination shape do not prove exfiltration. Backups, servers, collaboration tools and ordinary uploads look the same.

1. Treat unauthorised transfer as a proposition to test. Define which side is internal at the capture point; an originator in Zeek or a first address in a summary is not that.
2. Rank hosts, destinations and time windows (from `pcap_summary` rows or `zeek_run` connections) as triage views, then look for what ranking hides: small repeated transfers, long-lived channels, many destinations. One destination does not prove exfiltration; many do not prove sync or backup. Compare with the host's role, approved services and a baseline.
3. Label every number with its layer and direction before quoting it; the definitions are in `exfil/counters` (read it before you quote or compare a byte count). Never combine counters whose definitions differ.
4. Channels to consider: web uploads (a POST to a paste site), cloud sync, mail, file transfer (a scheduled SFTP job nobody remembers), ICMP payloads, DNS (slow, visible as query volume rather than bytes) and other permitted paths. Encrypted DNS can hide the query traits a tunnelling test needs.
5. A staging archive: record its real size, any safely established expanded size and the evidence tying it to a transfer. Its creation does not show an upload, and neither its size nor the wire volume says how many source bytes arrived. For the staging file use the installed platform's file-examination skills; a Windows-only skill applies only if that pack is loaded (check the run's tool inventory), otherwise record the missing capability.
6. Keep four questions apart: observed volume, evidence the transfer succeeded, identity of any recovered content, evidence it was unauthorised. Content can come from cleartext reconstruction, authorised decryption or specific endpoint or service records. With only encrypted lengths, say content and delivery are partial or undetermined.

Shows: bytes by a stated counter between named endpoints in a window. Does not show: what the data was, that it arrived, or that it was unauthorised. Record: counter, layer, direction, window, internal side and how it was decided.
