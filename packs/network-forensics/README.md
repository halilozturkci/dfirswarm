# Network Forensics Pack

Captures and flow logs: what the capture can contain, what survives encryption,
how to find something that calls home, and how to tie any of it to a machine.

Depends on the Computer Forensics Base Pack.

## What it carries

**Eight skills**: `capture/what-you-have`, `capture/carve-from-images`,
`sessions/reconstruct`, `metadata/dns-tls`, `beacons/periodicity`,
`exfil/volume`, `logs/web-proxy-firewall`, `correlate/host`.

**Six tools.** `pcap_summary` reads classic pcap and pcapng with **no external
dependency at all** — the parser is written here, because a forensic host
frequently has no Wireshark and the first four questions about a capture must
not depend on one. It returns the link type, the snap length, the time range,
conversations with bytes each way grouped per session or per endpoint, and the
connection start times a beacon check needs. `beacon_score` takes those times
and measures how tightly the intervals cluster around their own median, which is
what catches a jittered implant that a "are the intervals identical" test
misses. `zeek_run` drives Zeek where the host has it. `suricata_run` applies a
named local rules file and keeps the complete EVE log. `pcap_extract` performs
Wireshark object export and writes a provenance-and-hash index without placing
binary content in model output. `network_log_summary` parses Apache/Nginx access
logs, Squid access logs and common firewall key/value records into a complete
normalised TSV plus an aggregate summary.

**One catalogue recipe.** `network-capture` detects pcap and pcapng by magic,
then writes lossless packet, DNS, HTTP and TLS listings plus capture metadata.

**One goal template**: `what-left-the-network.md`.

## Two things the skills keep repeating

**The snap length decides what an answer can be worth.** A capture taken at 96
bytes holds headers and no payload, and every question about content is
unanswerable on it. That belongs in the report early, as a fact about the
evidence.

**Periodicity is not a verdict.** Update checks, telemetry, NTP, revocation
checks and monitoring agents beacon more reliably than most malware. The finding
is periodicity plus something that does not belong.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/network-forensics
    scripts/swarm.sh start --pack computer-forensics-base,network-forensics ...
