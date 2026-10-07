# Network Forensics Pack

Captures and flow logs: what the capture can contain, what survives encryption,
how to find something that calls home, and how to tie any of it to a machine.

Depends on the Computer Forensics Base Pack.

## What it carries

**Twelve skills**, as eight leaves of decision rules and four second-level
leaves they point to when needed: `capture/what-you-have` (and
`capture/derivatives`), `capture/carve-from-images`, `sessions/reconstruct` (and
`sessions/objects`), `metadata/dns-tls` (and `metadata/fingerprints`),
`beacons/periodicity`, `exfil/volume` (and `exfil/counters`),
`logs/web-proxy-firewall`, `correlate/host`.

**Six tools.** `pcap_summary` reads classic pcap and pcapng with **no external
dependency**: it returns a census of the capture (an interface table with link
type and snap length per interface, pcapng drop counters, the time range, packets
truncated and how much payload survived, and tuple or endpoint aggregates with
original and captured bytes kept apart) and SYN observations for a first
look at repeated connections. It is not a session engine. `beacon_score`
describes how tightly a series of event times clusters around its median
interval; a regular series is a lead, not a detection. `zeek_run` drives Zeek where
the host has it, loads a named hashing policy through a script it writes and
records, and reads the logs by their own headers. `suricata_run` runs a named
local rules file under an explicit configuration it tests first, and keeps the
complete EVE log. `pcap_extract` performs Wireshark object export with a receipt
from the first moment and ties an HTTP object to a frame when its bytes equal one
response body. `network_log_summary` reads Apache/nginx access logs, Squid native
logs and upper-case KEY=VALUE firewall records into a table with line numbers
and byte offsets and an explicit timestamp column. Tools that can reach request
data withhold credentials from their answers and keep their output private: run
them as jobs with `secret_output: true`. No tool here reads NetFlow, IPFIX or
cloud flow records; a flow export is identified and its semantics stated, not
parsed.

**One catalogue recipe.** `network-capture` detects pcap and pcapng by magic,
then writes capture metadata and complete listings of the selected fields of
every packet and of the DNS, HTTP and TLS packets (HTTP/2 and QUIC where the
installed tshark lists their fields), with a receipt from the first moment. It
is a broad extraction (`purpose: broad_extraction`), one tshark's reading and not
the capture: its `exclusions` say it reassembles no payload and reads no
encrypted TLS, and a table with no rows does not show a protocol is absent.

**One goal template**: `what-left-the-network.md`.

## Two things the skills keep repeating

**The snap length is a limit, not a verdict.** A capture taken at 96 bytes can
still hold payload (Ethernet, IPv4 and TCP headers take 54), and a longer
capture can cut it. What decides what an answer can be worth is how much of each
packet survived, which `pcap_summary` measures per packet, together with the
capture point, the clock and the gaps. State it early, as a fact about the
evidence.

**Periodicity is not a verdict.** Update checks, telemetry, NTP, revocation
checks and monitoring agents beacon more reliably than most malware. The finding
is periodicity plus something that does not belong.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/network-forensics
    scripts/swarm.sh start --pack computer-forensics-base,network-forensics ...
