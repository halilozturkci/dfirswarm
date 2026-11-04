# Network Forensics Pack

Packet captures and web, proxy and firewall logs: what a capture can contain,
what survives encryption, how to test for something that calls home, and how to
tie any of it to a machine. `flow_reader` reads flow records (NetFlow v5, v9, IPFIX) from an nfcapd file.

Depends on the Computer Forensics Base Pack.

## What it carries

**Seventeen skills**: the pack's router, `network/router` (at most 400 tokens: it names the other sixteen by the
question each answers, holds no rule, and is the one line a run shows for the pack when its skills index is over
budget), and, as twelve leaves of decision rules and four second-level
leaves they point to when needed: `capture/what-you-have` (and
`capture/derivatives`), `capture/carve-from-images`, `sessions/reconstruct` (and
`sessions/objects`), `metadata/dns-tls` (and `metadata/fingerprints`),
`metadata/encrypted-dns`, `beacons/periodicity`, `exfil/volume` (and `exfil/counters`),
`logs/web-proxy-firewall`, `correlate/host`, `evidence/captured-secrets`, `flows/interpret`,
`analysis/engines-and-coverage`.

**Ten tools.** `pcap_summary` reads classic pcap and pcapng with **no external
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
and byte offsets and an explicit timestamp column. `capture_transform` makes derivative
captures with `editcap`, `mergecap`, `tcpdump -r` and `text2pcap` (split, merge, filter, dedup,
convert, and a hex dump to a synthetic capture): it never writes the original, labels every
output "derivative, not evidence", and says how many packets went in, came out and were dropped.
`flow_reader` reads an nfcapd file (the NetFlow v5, v9 and IPFIX records nfdump's collector stored) with the declared
`nfdump`, as a reader: it never runs `nfcapd` or `nfpcapd`, and nothing listens on a port. It gives the exporters the file lists,
the times in UTC beside the collector's receive time, sampled counters apart from the others (a sampled record's counters are
never exact), the direction and translated fields nfdump names, and what an nfcapd file does not keep (templates, timeouts).
It refuses a capture and sFlow by name; nfdump exits 0 on a file it cannot read, so the file's messages and its own flow count
decide the status. `tls_decrypt` is a `secret_output` tool over `tshark`: it takes a capture, a key log as a FILE
reference (never its text) and/or a pcapng's own Decryption Secrets Blocks, and says for every TCP flow whether the secrets
decrypted it (`decrypted`, `partially`, `unsupported`, `no_secret_for_session`, `not_tls`) and why, in counts and locators only;
the decrypted bytes go to owner-only files under its output directory. It relies on tshark's TLS fields and `-z follow`, which
this build of the pack checks by name (`tshark -G fields`) but did not verify against a real capture. `quic_inspect` is a `secret_output` tool over `tshark` too: one row for every UDP datagram tshark dissects as QUIC (each coalesced packet with its header form, type, version, connection ids, token flag, and where tshark decoded them the SNI, ALPN, frame types and HTTP/3 stream ids), the limits of each row (`encrypted_payload`, `version_unsupported`, `dissector_missing`), and a connection model that keeps UDP tuples and connection ids apart (Retry and Version Negotiation end an attempt, migration is one attempt, a short header no long header named is an unlinked attempt). It counts the UDP port 443 datagrams tshark did not dissect as QUIC and infers nothing from `ssl.log`; its field names were not verified against a real capture. The tools that print text from the evidence (`pcap_extract`, `zeek_run`,
`suricata_run`, `network_log_summary`, `tls_decrypt`, `quic_inspect`, and the capture's own option text in
`pcap_summary`) keep their output in a private directory and withhold what
looks like a credential from their answers, column by column (by shape: a short
secret that does not look like a token is not recognised; a hash, GUID or UUID
is withheld too and recoverable in a job): run them as jobs with
`secret_output: true`. Every answer of the ten carries `status` (`complete`,
`partial` or `failed`) and `status_basis`, exit 0 means the engine ran, and
SIGTERM, SIGINT and SIGHUP end a tool with partial JSON, from the first lines of
its script on (six of the tools and the recipe install a minimal handler before
their other imports, which answers "stopped before any work" and exits 128 plus
the signal; `capture_transform`, `flow_reader`, `tls_decrypt` and `quic_inspect` install the handler of their stop block after four
imports, which answers status `failed` with `interrupted` true and exits 128 plus the signal). The one window left is the interpreter's own start and its compile
of the script, before the script's first line has run: a stop there gives no
answer. Measured on 2026-11-01 (SIGTERM at a random offset of 0-250 ms after the
start, 80 runs of each of those scripts, one CPU, no network; `capture_transform`, `flow_reader`, `tls_decrypt` and `quic_inspect` were not measured), 6 to 19 of 80 runs gave no
JSON, all but one of them within 55 ms of the start, on a quiet host; a busy host sees more (misses up to about 80 ms were seen). Flow
export is read by `flow_reader` from an nfcapd file only (NetFlow v5, v9, IPFIX; not sFlow, and not export packets inside a capture):
`flows/interpret` says what to settle first (the exporter, the sampling, the timeouts, what its counters mean).

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
