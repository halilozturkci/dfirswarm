#!/usr/bin/env python3
"""The export packets behind tests/fixtures/network-flow/, built from the protocol specifications and sent to a collector, never from a parser's output.

  NetFlow v5   Cisco's export format: a 24-byte header (version, count, sys uptime, unix secs and nsecs, flow sequence, engine type and id,
               sampling mode in the top two bits and interval in the low fourteen) and 48-byte records.
  NetFlow v9   RFC 3954: header (version, count, uptime, secs, sequence, source id), a template flowset (id 0) and a data flowset; the field
               types are RFC 3954's (IN_BYTES 1, IN_PKTS 2, PROTOCOL 4, TCP_FLAGS 6, L4_SRC_PORT 7, IPV4_SRC_ADDR 8, INPUT_SNMP 10, L4_DST_PORT 11,
               IPV4_DST_ADDR 12, OUTPUT_SNMP 14, LAST_SWITCHED 21, FIRST_SWITCHED 22, DIRECTION 61) and IANA's postNAT elements 225 to 228.
  IPFIX        RFC 7011: header (version 10, length, export time, sequence, observation domain), a template set (id 2) and a data set; the
               information elements are IANA's (flowStartMilliseconds 152, flowEndMilliseconds 153, the same 225 to 228 for the translated side).
  sFlow v5     sflow.org's datagram: one flow sample with one raw packet header record.

Two flows go into each file, the same in the three NetFlow/IPFIX forms:
  1. 10.0.0.5:50000 -> 203.0.113.7:443 TCP, flags 0x1b, 10 packets, 1500 bytes, 60 s to 30 s before the export, interfaces 3 -> 4, direction 0,
     translated source 192.0.2.10:40000 (v9 and IPFIX)
  2. 10.0.0.6:5353 -> 198.51.100.9:53 UDP, 2 packets, 120 bytes, 20 s to 19 s before the export, interfaces 3 -> 4, direction 1,
     translated source 192.0.2.10:40001 (v9 and IPFIX)
The export time is 1700000000 (2023-11-14T22:13:20Z), the uptime 3600000 ms. The v5 sampled form announces mode 1, interval 100.

The files were collected in a throwaway Debian 12 container with the distribution's nfdump 1.7.1 (`nfcapd -b 127.0.0.1 -p PORT -w DIR -I IDENT`,
this script as the exporter, nfcapd ended with SIGTERM), and `nfdump -r FILE -w OUT -y` made the lz4 copy. The recorded outputs in recorded.json
are what that nfdump printed (`-V`, `-v`, `-I -r`, `-E` and `-r FILE -o json`, with TZ=UTC) for each file.

Usage: network-flow-fixture.py KIND HOST PORT   with KIND one of v5, v5s, v9, ipfix, sflow
"""
import ipaddress
import socket
import struct
import sys
import time

BASE = 1_700_000_000
UPTIME = 3_600_000


def ip(address):
    return ipaddress.IPv4Address(address).packed


def v5(sampling=0):
    rows = [
        ("10.0.0.5", "203.0.113.7", "10.0.0.1", 3, 4, 10, 1500, UPTIME - 60_000, UPTIME - 30_000, 50000, 443, 0x1B, 6, 0, 64512, 64496, 24, 24),
        ("10.0.0.6", "198.51.100.9", "10.0.0.1", 3, 4, 2, 120, UPTIME - 20_000, UPTIME - 19_000, 5353, 53, 0, 17, 0, 0, 0, 24, 24),
    ]
    out = struct.pack(">HHIIIIBBH", 5, len(rows), UPTIME, BASE, 250_000_000, 100, 1, 7, sampling)
    for r in rows:
        out += ip(r[0]) + ip(r[1]) + ip(r[2]) + struct.pack(">HHIIIIHHxBBBHHBBxx", *r[3:])
    return [out]


def template(fields):
    return b"".join(struct.pack(">HH", t, n) for t, n in fields)


V9_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (6, 1), (1, 4), (2, 4), (22, 4), (21, 4), (10, 2), (14, 2), (61, 1), (225, 4), (226, 4), (227, 2), (228, 2)]
IPFIX_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (6, 2), (1, 8), (2, 8), (152, 8), (153, 8), (10, 4), (14, 4), (61, 1), (225, 4), (226, 4), (227, 2), (228, 2)]


def v9(source_id=42):
    tid = 256
    tmpl = struct.pack(">HH", tid, len(V9_FIELDS)) + template(V9_FIELDS)
    flowset_t = struct.pack(">HH", 0, 4 + len(tmpl)) + tmpl
    records = (
        ip("10.0.0.5") + ip("203.0.113.7") + struct.pack(">HHBBIIIIHHB", 50000, 443, 6, 0x1B, 1500, 10, UPTIME - 60_000, UPTIME - 30_000, 3, 4, 0)
        + ip("192.0.2.10") + ip("203.0.113.7") + struct.pack(">HH", 40000, 443)
        + ip("10.0.0.6") + ip("198.51.100.9") + struct.pack(">HHBBIIIIHHB", 5353, 53, 17, 0, 120, 2, UPTIME - 20_000, UPTIME - 19_000, 3, 4, 1)
        + ip("192.0.2.10") + ip("198.51.100.9") + struct.pack(">HH", 40001, 53)
    )
    pad = (-(4 + len(records))) % 4
    flowset_d = struct.pack(">HH", tid, 4 + len(records) + pad) + records + b"\0" * pad
    return [struct.pack(">HHIIII", 9, 3, UPTIME, BASE, 1, source_id) + flowset_t + flowset_d]


def ipfix(domain=7):
    tid = 300
    tmpl = struct.pack(">HH", tid, len(IPFIX_FIELDS)) + template(IPFIX_FIELDS)
    set_t = struct.pack(">HH", 2, 4 + len(tmpl)) + tmpl
    ms = BASE * 1000
    records = (
        ip("10.0.0.5") + ip("203.0.113.7") + struct.pack(">HHBHQQQQIIB", 50000, 443, 6, 0x1B, 1500, 10, ms - 60_000, ms - 30_000, 3, 4, 0)
        + ip("192.0.2.10") + ip("203.0.113.7") + struct.pack(">HH", 40000, 443)
        + ip("10.0.0.6") + ip("198.51.100.9") + struct.pack(">HHBHQQQQIIB", 5353, 53, 17, 0, 120, 2, ms - 20_000, ms - 19_000, 3, 4, 1)
        + ip("192.0.2.10") + ip("198.51.100.9") + struct.pack(">HH", 40001, 53)
    )
    pad = (-(4 + len(records))) % 4
    set_d = struct.pack(">HH", tid, 4 + len(records) + pad) + records + b"\0" * pad
    body = set_t + set_d
    return [struct.pack(">HHIII", 10, 16 + len(body), BASE, 0, domain) + body]


def sflow():
    eth = bytes.fromhex("aabbccddeeff112233445566") + struct.pack(">H", 0x0800)
    iph = struct.pack(">BBHHHBBH", 0x45, 0, 40, 1, 0, 64, 6, 0) + ip("10.0.0.5") + ip("203.0.113.7")
    tcp = struct.pack(">HHIIBBHHH", 50000, 443, 1, 0, 0x50, 0x10, 8192, 0, 0)
    header = eth + iph + tcp
    pad = (-len(header)) % 4
    record_body = struct.pack(">IIII", 1, 1500, 4, len(header)) + header + b"\0" * pad
    record = struct.pack(">II", 1, len(record_body)) + record_body
    sample_body = struct.pack(">IIIIIII", 1, 3, 512, 1000, 0, 3, 4) + struct.pack(">I", 1) + record
    sample = struct.pack(">II", 1, len(sample_body)) + sample_body
    return [struct.pack(">II", 5, 1) + ip("192.0.2.77") + struct.pack(">IIII", 5, 9, 5000, 1) + sample]


def main():
    kind, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    packets = {"v5": v5, "v5s": lambda: v5((1 << 14) | 100), "v9": v9, "ipfix": ipfix, "sflow": sflow}[kind]()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for packet in packets:
        sock.sendto(packet, (host, port))
        time.sleep(0.2)


if __name__ == "__main__":
    main()
