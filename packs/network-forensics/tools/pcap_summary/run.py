#!/usr/bin/env python3
"""Read a capture without needing tshark on the host.

The parser is written here rather than taken from a library for one reason: a
forensic host frequently has no Wireshark, and the first four questions about a
capture — how long, how much, between whom, and was the payload even kept — must
not depend on that.

Both container formats are read:

    classic pcap   one global header, then per packet a timestamp, the captured
                   length and the original length
    pcapng         blocks; the section header, one interface description per
                   interface with its own link type and time resolution, and
                   enhanced packet blocks carrying the data

The snap length is the first thing to look at and the output puts it near the
top. A capture taken at 96 bytes holds headers and no payload, so every question
about content is unanswerable on it — a fact about the evidence, not a failure
of the analysis.
"""
import binascii
import collections
import datetime
import json
import os
import struct
import sys

LINKTYPES = {0: "null", 1: "Ethernet", 9: "PPP", 101: "raw IP", 105: "802.11",
             113: "Linux cooked", 127: "802.11 radiotap", 228: "IPv4", 229: "IPv6",
             276: "Linux cooked v2"}
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 47: "GRE", 50: "ESP"}


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def address(raw, six=False):
    if six:
        parts = [binascii.hexlify(raw[i:i + 2]).decode() for i in range(0, 16, 2)]
        return ":".join(p.lstrip("0") or "0" for p in parts)
    return ".".join(str(b) for b in raw)


def read_classic(fh):
    head = fh.read(24)
    if len(head) < 24:
        raise ValueError("shorter than a pcap header")
    magic = head[:4]
    if magic == b"\xa1\xb2\xc3\xd4":
        end, divisor = ">", 1_000_000
    elif magic == b"\xd4\xc3\xb2\xa1":
        end, divisor = "<", 1_000_000
    elif magic == b"\xa1\xb2\x3c\x4d":
        end, divisor = ">", 1_000_000_000
    elif magic == b"\x4d\x3c\xb2\xa1":
        end, divisor = "<", 1_000_000_000
    else:
        raise ValueError("not a classic pcap")
    major, minor, _zone, _sig, snaplen, network = struct.unpack(end + "HHiIII", head[4:])
    meta = {"format": "pcap", "version": "%d.%d" % (major, minor), "snap_length": snaplen,
            "link_type": LINKTYPES.get(network, str(network)), "link_type_id": network}
    def packets():
        while True:
            header = fh.read(16)
            if len(header) == 0:
                return
            if len(header) < 16:
                raise ValueError("truncated classic pcap packet header")
            sec, frac, incl, orig = struct.unpack(end + "IIII", header)
            body = fh.read(incl)
            if len(body) < incl:
                raise ValueError("truncated classic pcap packet body: wanted %d bytes, found %d" % (incl, len(body)))
            yield sec + frac / divisor, body, orig, network
    return meta, packets


def read_pcapng(fh):
    fh.seek(0)
    meta = {"format": "pcapng", "snap_length": None, "link_type": None}
    if fh.read(4) != b"\x0a\x0d\x0d\x0a":
        raise ValueError("not a pcapng section header")
    fh.seek(0)

    def options(body, at, end):
        found = {}
        while at + 4 <= len(body):
            code, size = struct.unpack(end + "HH", body[at:at + 4])
            at += 4
            if code == 0:
                break
            if at + size > len(body):
                break
            found.setdefault(code, []).append(body[at:at + size])
            at += (size + 3) & ~3
        return found

    def packets():
        interfaces = []
        end = "<"
        while True:
            header = fh.read(8)
            if len(header) == 0:
                return
            if len(header) < 8:
                raise ValueError("truncated pcapng block header")
            raw_type, raw_total = header[:4], header[4:]
            if raw_type == b"\x0a\x0d\x0d\x0a":
                magic = fh.read(4)
                if magic == b"\x4d\x3c\x2b\x1a":
                    end = "<"
                elif magic == b"\x1a\x2b\x3c\x4d":
                    end = ">"
                else:
                    raise ValueError("pcapng section has an invalid byte-order magic")
                total = struct.unpack(end + "I", raw_total)[0]
                if total < 28 or total > (1 << 28):
                    raise ValueError("pcapng section has an invalid block length")
                rest = fh.read(total - 16)
                trailer = fh.read(4)
                if len(rest) != total - 16 or len(trailer) != 4 or struct.unpack(end + "I", trailer)[0] != total:
                    raise ValueError("truncated or inconsistent pcapng section")
                interfaces = []
                continue
            block_type, total = struct.unpack(end + "II", header)
            if total < 12 or total > (1 << 28):
                raise ValueError("pcapng block has an invalid length")
            body = fh.read(total - 12)
            trailer = fh.read(4)
            if len(body) != total - 12 or len(trailer) != 4 or struct.unpack(end + "I", trailer)[0] != total:
                raise ValueError("truncated or inconsistent pcapng block")
            if block_type == 0x00000001 and len(body) >= 8:
                link, _res, snap = struct.unpack(end + "HHI", body[:8])
                opts = options(body, 8, end)
                raw_resolution = opts.get(9, [b"\x06"])[0][0]
                divisor = (2 ** (raw_resolution & 0x7f)) if raw_resolution & 0x80 else (10 ** raw_resolution)
                offset = 0
                if opts.get(14) and len(opts[14][0]) == 8:
                    offset = struct.unpack(end + "q", opts[14][0])[0]
                interfaces.append({"link_type": link, "snap_length": snap,
                                   "divisor": divisor, "offset": offset})
                if meta["link_type"] is None:
                    meta["link_type"] = LINKTYPES.get(link, str(link))
                    meta["link_type_id"] = link
                    meta["snap_length"] = snap
            elif block_type == 0x00000006 and len(body) >= 20:
                iface, high, low, incl, orig = struct.unpack(end + "IIIII", body[:20])
                if iface >= len(interfaces) or 20 + incl > len(body):
                    raise ValueError("pcapng packet names an invalid interface or length")
                info = interfaces[iface]
                ticks = (high << 32) | low
                when = ticks / info["divisor"] + info["offset"]
                yield when, body[20:20 + incl], orig, info.get("link_type", 1)
            elif block_type == 0x00000003 and len(body) >= 4:
                if not interfaces:
                    raise ValueError("pcapng simple packet block appears before an interface")
                orig = struct.unpack(end + "I", body[:4])[0]
                snap = interfaces[0]["snap_length"]
                captured = min(orig, snap) if snap else orig
                padded = (captured + 3) & ~3
                if len(body) - 4 != padded:
                    raise ValueError("pcapng simple packet block has an inconsistent captured length")
                yield None, body[4:4 + captured], orig, interfaces[0]["link_type"]
    return meta, packets


def dissect(body, link):
    """Return src, dst, protocol, sport, dport — or None when it is not IP."""
    if link == 1:
        if len(body) < 14:
            return None
        kind = struct.unpack(">H", body[12:14])[0]
        at = 14
        while kind in (0x8100, 0x88a8) and len(body) >= at + 4:
            kind = struct.unpack(">H", body[at + 2:at + 4])[0]
            at += 4
    elif link in (101, 228, 229):
        kind, at = (0x0800 if link != 229 else 0x86dd), 0
        if link == 101 and body:
            kind = 0x0800 if (body[0] >> 4) == 4 else 0x86dd
    elif link == 113:
        if len(body) < 16:
            return None
        kind, at = struct.unpack(">H", body[14:16])[0], 16
    elif link == 276:
        if len(body) < 20:
            return None
        kind, at = struct.unpack(">H", body[0:2])[0], 20
    elif link == 0:
        if len(body) < 4:
            return None
        family_le, family_be = struct.unpack("<I", body[:4])[0], struct.unpack(">I", body[:4])[0]
        family = family_le if family_le in (2, 10, 24, 28, 30) else family_be
        kind, at = (0x0800 if family == 2 else 0x86dd), 4
    else:
        return None

    if kind == 0x0800:
        if len(body) < at + 20:
            return None
        ihl = (body[at] & 0x0F) * 4
        if ihl < 20 or len(body) < at + ihl:
            return None
        protocol = body[at + 9]
        src, dst = address(body[at + 12:at + 16]), address(body[at + 16:at + 20])
        transport = at + ihl
        fragment = struct.unpack(">H", body[at + 6:at + 8])[0]
        if fragment & 0x1fff:
            transport = len(body)
        six = False
    elif kind == 0x86dd:
        if len(body) < at + 40:
            return None
        protocol = body[at + 6]
        src, dst = address(body[at + 8:at + 24], True), address(body[at + 24:at + 40], True)
        transport = at + 40
        while protocol in (0, 43, 44, 51, 60) and transport + 2 <= len(body):
            following = body[transport]
            if protocol == 44:
                if transport + 8 > len(body):
                    return None
                fragment = struct.unpack(">H", body[transport + 2:transport + 4])[0]
                transport += 8
                protocol = following
                if fragment & 0xfff8:
                    transport = len(body)
                    break
            elif protocol == 51:
                size = (body[transport + 1] + 2) * 4
                transport += size
                protocol = following
            else:
                size = (body[transport + 1] + 1) * 8
                transport += size
                protocol = following
        six = True
    else:
        return None

    sport = dport = None
    flags = 0
    if protocol in (6, 17) and len(body) >= transport + 4:
        sport, dport = struct.unpack(">HH", body[transport:transport + 4])
        if protocol == 6 and len(body) >= transport + 14:
            flags = body[transport + 13]
    return {"src": src, "dst": dst, "protocol": PROTOCOLS.get(protocol, str(protocol)),
            "sport": sport, "dport": dport, "syn_only": protocol == 6 and flags & 0x12 == 0x02,
            "six": six}


def iso(stamp):
    if stamp is None:
        return None
    try:
        return datetime.datetime.fromtimestamp(
            stamp, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def checked_packets(factory, path):
    try:
        yield from factory()
    except (ValueError, struct.error) as exc:
        fail("capture ended malformed or truncated", path=path, reason=str(exc))


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a .pcap or .pcapng file")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    top = args.get("top")
    if top is not None and (not isinstance(top, int) or isinstance(top, bool) or top < 1):
        fail("top must be a positive integer")
    if "max_packets" in args:
        fail("max_packets is not supported: a forensic summary must read the whole capture")
    out_dir = args.get("out_dir")
    if out_dir is not None and (not isinstance(out_dir, str) or not out_dir):
        fail("out_dir must be a non-empty string")
    if out_dir and os.path.exists(out_dir) and os.listdir(out_dir):
        fail("out_dir already holds files", out_dir=out_dir)
    only_host = args.get("host")
    only_port = args.get("port")
    group_by_endpoint = str(args.get("group") or "session").lower() == "endpoint"
    if str(args.get("group") or "session").lower() not in ("session", "endpoint"):
        fail("group must be session or endpoint", group=args.get("group"))

    with open(path, "rb") as fh:
        try:
            meta, packets = read_classic(fh)
        except ValueError:
            try:
                meta, packets = read_pcapng(fh)
            except (ValueError, struct.error) as exc:
                fail("this is neither a classic pcap nor a pcapng", path=path, reason=str(exc))

        conversations = {}
        by_port = collections.Counter()
        by_protocol = collections.Counter()
        talkers = collections.Counter()
        first = last = None
        count = undissected = truncated_payload = 0
        for when, body, orig, link in checked_packets(packets, path):
            count += 1
            if when is not None:
                first = when if first is None else min(first, when)
                last = when if last is None else max(last, when)
            if orig > len(body):
                truncated_payload += 1
            found = dissect(body, link)
            if not found:
                undissected += 1
                continue
            if only_host and only_host not in (found["src"], found["dst"]):
                continue
            if only_port is not None and only_port not in (found["sport"], found["dport"]):
                continue
            by_protocol[found["protocol"]] += 1
            if found["dport"] is not None:
                by_port[found["dport"]] += 1
            talkers[found["src"]] += len(body)
            if group_by_endpoint:
                # Ignore the ephemeral port, so every connection to one service
                # lands in one row — which is what a beacon check needs.
                low, high = found["sport"] or 0, found["dport"] or 0
                service = min(low, high) if low and high else (low or high)
                key = tuple(sorted([(found["src"], None), (found["dst"], None)])) + \
                    (found["protocol"], service)
            else:
                key = tuple(sorted([(found["src"], found["sport"]),
                                    (found["dst"], found["dport"])])) + (found["protocol"], None)
            entry = conversations.setdefault(key, {
                "a": key[0][0], "a_port": key[0][1], "b": key[1][0], "b_port": key[1][1],
                "protocol": found["protocol"], "service_port": key[3], "packets": 0, "bytes": 0,
                "a_to_b_bytes": 0, "b_to_a_bytes": 0, "first": when, "last": when, "starts": []})
            entry["packets"] += 1
            entry["bytes"] += orig
            if group_by_endpoint:
                source_endpoint = (found["src"], found["sport"] if found["sport"] is not None else -1)
                destination_endpoint = (found["dst"], found["dport"] if found["dport"] is not None else -1)
                source_is_a = source_endpoint <= destination_endpoint
            else:
                source_is_a = (found["src"], found["sport"]) == key[0]
            if source_is_a:
                entry["a_to_b_bytes"] += orig
            else:
                entry["b_to_a_bytes"] += orig
            if when is not None:
                entry["first"] = when if entry["first"] is None else min(entry["first"], when)
                entry["last"] = when if entry["last"] is None else max(entry["last"], when)
                if found["syn_only"]:
                    entry["starts"].append(round(when, 6))

    complete = sorted(conversations.values(), key=lambda c: -c["bytes"])
    conversations_path = None
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        conversations_path = os.path.join(out_dir, "conversations.tsv")
        with open(conversations_path, "w", encoding="utf-8", newline="\n") as out:
            out.write("a\ta_port\tb\tb_port\tprotocol\tservice_port\tpackets\tbytes\ta_to_b_bytes\tb_to_a_bytes\tfirst\tlast\tstarts_json\n")
            for entry in complete:
                values = [entry["a"], entry["a_port"], entry["b"], entry["b_port"], entry["protocol"],
                          entry["service_port"], entry["packets"], entry["bytes"], entry["a_to_b_bytes"],
                          entry["b_to_a_bytes"], iso(entry["first"]), iso(entry["last"]),
                          json.dumps(entry["starts"], separators=(",", ":"))]
                out.write("\t".join("" if value is None else str(value) for value in values) + "\n")
    if top is not None and len(complete) > top and not conversations_path:
        fail("top would omit conversations; provide out_dir to keep the complete conversations.tsv",
             conversation_count=len(complete), requested=top)
    ranked = complete[:top] if top is not None else complete
    for entry in ranked:
        entry["first"] = iso(entry["first"])
        entry["last"] = iso(entry["last"])
        if not args.get("with_starts"):
            entry["connection_starts"] = len(entry.pop("starts"))
        else:
            entry["connection_starts"] = len(entry["starts"])

    notes = []
    if meta.get("snap_length") and meta["snap_length"] < 1500:
        notes.append("The snap length is %d bytes: this capture holds headers and little or no "
                     "payload, so questions about content cannot be answered from it."
                     % meta["snap_length"])
    if truncated_payload:
        notes.append("%d packets were captured shorter than they were on the wire."
                     % truncated_payload)
    if undissected:
        notes.append("%d packets were not IP, or used a link type this parser does not decode."
                     % undissected)

    print(json.dumps({
        "path": path, "bytes": os.path.getsize(path), **meta,
        "packets": count,
        "first_packet": iso(first), "last_packet": iso(last),
        "duration_seconds": round(last - first, 3) if first is not None and last is not None else None,
        "conversations": ranked,
        "conversation_count": len(conversations),
        "conversations_returned": len(ranked),
        "conversations_omitted": len(conversations) - len(ranked),
        "conversations_tsv": conversations_path,
        "top_talkers": [{"address": a, "bytes": b} for a, b in talkers.most_common()],
        "top_ports": [{"port": p, "packets": c} for p, c in by_port.most_common()],
        "protocols": dict(by_protocol),
        "notes": notes,
        "note": "Packet times come from the capturing machine, not from either endpoint, and "
                "nothing in the file says whether that clock was right. Before correlating with "
                "host artefacts, find one event visible in both, measure the offset and state it.",
    }, indent=2))


if __name__ == "__main__":
    main()
