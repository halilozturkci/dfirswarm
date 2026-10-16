# Network Forensics Pack

Packet captures and web, proxy and firewall logs: what a capture can contain,
what survives encryption, how to test for something that calls home, and how to
tie any of it to a machine. No tool here reads flow records (NetFlow, IPFIX).

Depends on the Computer Forensics Base Pack.

## What it carries

**Thirteen skills**: the pack's router, `network/router` (at most 400 tokens: it names the other twelve by the
question each answers, holds no rule, and is the one line a run shows for the pack when its skills index is over
budget), and, as eight leaves of decision rules and four second-level
leaves they point to when needed: `capture/what-you-have` (and
`capture/derivatives`), `capture/carve-from-images`, `sessions/reconstruct` (and
`sessions/objects`), `metadata/dns-tls` (and `metadata/fingerprints`),
`beacons/periodicity`, `exfil/volume` (and `exfil/counters`),
`logs/web-proxy-firewall`, `correlate/host`.

**Six tools.** `pcap_summary` reads classic pcap and pcapng with **no external
dependency**: it returns a census of the capture (an interface table with link
type and snap length per interface, pcapng drop counters, the time range, packets
truncated and how much payload survived, and tuple or endpoint aggregates with
original and captured bytes kept apart) and SYN events (a SYN sent again within 120 seconds is folded into the first) for a first
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
and byte offsets and an explicit timestamp column. The tools that print text from the evidence (`pcap_extract`, `zeek_run`,
`suricata_run`, `network_log_summary`, and the capture's own option text in
`pcap_summary`) keep their output in a private directory and withhold what
looks like a credential from their answers, column by column (by shape: a short
secret that does not look like a token is not recognised; a hash, GUID or UUID
is withheld too and recoverable in a job): run them as jobs with
`secret_output: true`. Every answer of the six carries `status` (`complete`,
`partial` or `failed`) and `status_basis`, exit 0 means the engine ran, and
SIGTERM, SIGINT and SIGHUP end a tool with partial JSON. A
flow export is identified and its semantics stated, not parsed.

**One catalogue recipe.** `network-capture` detects pcap and pcapng by magic,
then writes capture metadata and complete listings of the selected fields of
every packet and of the DNS, HTTP and TLS packets (HTTP/2 and QUIC where the
installed tshark lists their fields; a field the build lacks is named and left
out), with a receipt from the first moment. The directory is private (0700,
files 0600) and the tables that can hold names and URIs are marked
`secret_bearing`. It
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
