#!/usr/bin/env python3
"""Read a capture without needing tshark on the host, and say what was measured.

The parser is written here rather than taken from a library for one reason: a
forensic host frequently has no Wireshark, and the first questions about a
capture (how long, how much, between whom, how much of each packet was kept)
must not depend on that. It is a census, not an authoritative session engine.

Both container formats are read:

    classic pcap   one global header, then per packet a timestamp, the captured
                   length and the original length
    pcapng         blocks: a section header, one interface description per
                   interface with its own link type and time resolution,
                   enhanced, simple and (obsolete) packet blocks carrying the
                   data, interface statistics blocks carrying the capturing
                   interface's own drop counters. Every other block is counted
                   by type and reported as not decoded.

What the answer holds, and what it does not:

    tuple_conversations / endpoint_aggregates
        One row per sorted pair of (address, port) and protocol, or per pair of
        addresses and a service port. They are AGGREGATES, not TCP sessions: a
        tuple used again later merges with its earlier use. syn_observations
        counts SYN-only packets; syn_unique counts distinct (sender, sequence
        number) pairs, which removes a SYN sent again and nothing else: it says
        nothing about whether a handshake completed.
    bytes_original / bytes_captured
        Two different lengths, never mixed: the original frame length each packet
        record declares, and the bytes the capture kept. Neither is application
        data delivered.
    truncation
        Measured per packet: how many packets were captured shorter than they
        were on the wire, by protocol, how many bytes that cut, and how much TCP
        or UDP payload survived. The snap length is a bound on what could be
        kept, not a statement of what was.
    service_port_basis
        Where the service port of an endpoint row came from: the destination of
        a SYN, the source of a SYN/ACK, or (when the capture holds no handshake)
        the smaller of the two port numbers, said to be a guess.

Aggregates are held in memory up to max_memory_tuples keys and are kept in a
temporary SQLite file beyond that, so memory does not follow the capture; the
answer says so (spilled_to_disk). Whole results are kept on disk and named when
a page is shorter than the result.
"""
import collections
import datetime
import ipaddress
import json
import os
import re
import secrets
import signal
import sqlite3
import struct
import sys
import tempfile
from pathlib import Path

TOOL = {"name": "pcap_summary", "version": 4}
PARSER = "pcap_summary/4"
LINKTYPES = {0: "null", 1: "Ethernet", 9: "PPP", 101: "raw IP", 105: "802.11",
             113: "Linux cooked", 127: "802.11 radiotap", 228: "IPv4", 229: "IPv6",
             276: "Linux cooked v2"}
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 47: "GRE", 50: "ESP"}
NG_BLOCKS = {0x0A0D0D0A: "section_header", 1: "interface_description", 2: "packet_obsolete", 3: "simple_packet",
             4: "name_resolution", 5: "interface_statistics", 6: "enhanced_packet", 0x0A: "decryption_secrets",
             0x00000BAD: "custom", 0x40000BAD: "custom"}
# Blocks whose content this tool does not decode: counted by type, never silently skipped. A decryption
# secrets block holds key material: it is counted and never read out.
NG_NOT_DECODED = {"name_resolution", "decryption_secrets", "custom"}
MAX_RECORD = 64 << 20          # a record claiming more than this is a corrupt header, not a packet
MAX_BLOCK = 1 << 28
DEFAULT_TOP = 200
DEFAULT_MAX_MEMORY_TUPLES = 200_000


def describe(exc):
    return "%s: %s" % (type(exc).__name__, getattr(exc, "strerror", None) or str(exc))


CLEANUP = []   # what to undo when the run ends early: the temporary aggregate file above all


def cleanup():
    while CLEANUP:
        try:
            CLEANUP.pop()()
        except Exception:  # noqa: BLE001 - best effort, and never a second failure over the first
            pass


def fail(message, **extra):
    cleanup()
    print(json.dumps({"error": message, "tool": TOOL, **extra}))
    raise SystemExit(1)


def _on_signal(signum, _frame):
    cleanup()
    os._exit(128 + signum)


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place
    outside it, the run directory itself, or anything under inputs/ is refused.

    A string check is not enough: `work/../inputs/x`, an absolute path and a
    symlink that points out all name a place the tool must not write, and none
    of them starts with "inputs/". Resolving first and comparing directories
    is what actually holds, and the read-only inputs are the one place
    extracted bytes must never appear -- a later integrity check would report
    the evidence as modified. In a job $OUT is inside the run directory, and is
    the one place a job writes.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("%s must stay inside the run directory" % what, **{what: str(out)})
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("%s cannot be under inputs/" % what, **{what: str(out)})
    if in_job():
        job_out = Path(os.environ["OUT"]).resolve()
        if dest != job_out and job_out not in dest.parents:
            fail("in a job %s is a directory under $OUT, the one place a job writes" % what, **{what: str(out), "out": str(job_out)})
    return str(dest.relative_to(root))


# Lossless paging (the same in every pack tool that pages): the page an agent reads stays small, and when there
# are more rows the whole result is written as JSON Lines under work/<agent>/tool-output (in a job,
# $OUT/tool-output) and named. The file name is random, never a digest of anything asked for, so two requests
# never share a file and a later run never replaces an earlier result. Rows are written as JSON escapes: a name
# that is not UTF-8 reaches Python as lone surrogates, which a UTF-8 file cannot hold and a JSON escape can.
class LosslessPage:
    def __init__(self, tool, limit):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise ValueError("limit must be a non-negative integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page = []
        self.total = 0
        self._out = None
        self._tmp = None
        name = "%s-%s.jsonl" % (self.tool, secrets.token_hex(8))
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row):
        self._out.write(json.dumps(row, ensure_ascii=True, default=str))
        self._out.write("\n")

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            os.replace(self._tmp, self.path)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


# --- addresses and times -------------------------------------------------------------------------------------

def ipv6_text(raw):
    """RFC 5952 text for 16 bytes, written here so it does not change with the Python version
    (3.13 prints an IPv4-mapped address differently from 3.12)."""
    groups = struct.unpack(">8H", raw)
    best_at = best_len = run_at = run_len = 0
    for i, g in enumerate(groups + (1,)):
        if g == 0:
            if run_len == 0:
                run_at = i
            run_len += 1
        else:
            if run_len > best_len:
                best_at, best_len = run_at, run_len
            run_len = 0
    if best_len < 2:
        return ":".join("%x" % g for g in groups)
    left = ":".join("%x" % g for g in groups[:best_at])
    right = ":".join("%x" % g for g in groups[best_at + best_len:])
    return left + "::" + right


def address(raw, six=False):
    if six:
        return ipv6_text(raw)
    return ".".join(str(b) for b in raw)


def normal_host(text):
    """An address as the dissector writes it, whatever spelling the caller used; None when it is no address."""
    try:
        parsed = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    return ipv6_text(parsed.packed) if parsed.version == 6 else str(parsed)


def fmt_ns(ns, digits):
    if ns is None:
        return None
    try:
        whole, frac = divmod(ns, 1_000_000_000)
        stamp = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=whole)
    except (OverflowError, ValueError):
        return None
    text = stamp.strftime("%Y-%m-%dT%H:%M:%S")
    if digits:
        text += "." + ("%09d" % frac)[:digits]
    return text + "Z"


def resolution_of(raw):
    """(ticks per second, decimal digits of the fraction) from an if_tsresol byte: bit 7 set means 2^-n, else 10^-n."""
    if raw & 0x80:
        return 2 ** (raw & 0x7F), 9
    return 10 ** raw, min(9, raw)


# --- the two containers --------------------------------------------------------------------------------------

class Info:
    """What the container said about itself, filled in while the packets are read."""

    def __init__(self):
        self.format = None
        self.version = None
        self.interfaces = []          # one dict per interface description, across sections
        self.blocks = collections.Counter()
        self.not_decoded = collections.Counter()
        self.unknown = collections.Counter()
        self.stats = []               # interface statistics blocks
        self.section_options = []     # what a section header says about the capturing machine
        self.malformed_options = 0
        self.sections = 0


def read_classic(fh, info):
    head = fh.read(24)
    if len(head) < 24:
        raise ValueError("shorter than a pcap header")
    magic = head[:4]
    if magic == b"\xa1\xb2\xc3\xd4":
        end, tps = ">", 1_000_000
    elif magic == b"\xd4\xc3\xb2\xa1":
        end, tps = "<", 1_000_000
    elif magic == b"\xa1\xb2\x3c\x4d":
        end, tps = ">", 1_000_000_000
    elif magic == b"\x4d\x3c\xb2\xa1":
        end, tps = "<", 1_000_000_000
    else:
        raise ValueError("not a classic pcap")
    major, minor, _zone, _sig, snaplen, network = struct.unpack(end + "HHiIII", head[4:])
    info.format = "pcap"
    info.version = "%d.%d" % (major, minor)
    # The link-type field holds the type in its low 26 bits; bit 26 says the frames end in an FCS whose length (in
    # 16-bit words) is bits 28 to 31 (the pcap savefile format, as libpcap reads it). The high bits are not a type.
    link = network & 0x03FFFFFF
    row = {"section": 0, "interface": 0, "link_type": LINKTYPES.get(link, str(link)),
           "link_type_id": link, "snap_length": snaplen or None, "ticks_per_second": tps,
           "digits": 6 if tps == 1_000_000 else 9, "time_offset_seconds": 0,
           "packets": 0, "bytes_original": 0, "bytes_captured": 0, "options_malformed": 0}
    if network & 0x04000000:
        row["fcs_length_bytes"] = ((network >> 28) & 0xF) * 2
    elif network & ~0x03FFFFFF:
        row["link_type_field_raw"] = network
    info.interfaces.append(row)

    def packets():
        scale = 1_000_000_000 // tps
        while True:
            header = fh.read(16)
            if len(header) == 0:
                return
            if len(header) < 16:
                raise ValueError("truncated classic pcap packet header")
            sec, frac, incl, orig = struct.unpack(end + "IIII", header)
            if incl > MAX_RECORD:
                raise ValueError("record declares a captured length of %d bytes, more than the %d this tool accepts for one packet" % (incl, MAX_RECORD))
            body = fh.read(incl)
            if len(body) < incl:
                raise ValueError("truncated classic pcap packet body: wanted %d bytes, found %d" % (incl, len(body)))
            yield sec * 1_000_000_000 + frac * scale, body, orig, 0, (sec * tps + frac, tps, 0)
    return packets


def ng_options(body, at, end, info, owner=None):
    """Options from `at` on. An option whose declared length runs past the block is counted, here and on its owner."""
    found = {}
    while at + 4 <= len(body):
        code, size = struct.unpack(end + "HH", body[at:at + 4])
        at += 4
        if code == 0:
            break
        if at + size > len(body):
            info.malformed_options += 1
            if owner is not None:
                owner["options_malformed"] += 1
            break
        found.setdefault(code, []).append(body[at:at + size])
        at += (size + 3) & ~3
    return found


def text_of(raw):
    return raw.decode("utf-8", "replace")


def read_pcapng(fh, info):
    fh.seek(0)
    if fh.read(4) != b"\x0a\x0d\x0d\x0a":
        raise ValueError("not a pcapng section header")
    fh.seek(0)
    info.format = "pcapng"

    def packets():
        local = {}            # interface id in this section -> index in info.interfaces
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
                if total < 28 or total > MAX_BLOCK:
                    raise ValueError("pcapng section has an invalid block length")
                rest = fh.read(total - 16)
                trailer = fh.read(4)
                if len(rest) != total - 16 or len(trailer) != 4 or struct.unpack(end + "I", trailer)[0] != total:
                    raise ValueError("truncated or inconsistent pcapng section")
                if info.version is None:
                    info.version = "%d.%d" % struct.unpack(end + "HH", rest[:4])
                section_opts = ng_options(rest, 12, end, info)
                section = {"section": info.sections}
                for code, label in ((2, "hardware"), (3, "os"), (4, "application")):
                    if section_opts.get(code):
                        section[label] = text_of(section_opts[code][0])
                if len(section) > 1:
                    info.section_options.append(section)
                info.blocks["section_header"] += 1
                info.sections += 1
                local = {}
                continue
            block_type, total = struct.unpack(end + "II", header)
            if total < 12 or total > MAX_BLOCK:
                raise ValueError("pcapng block has an invalid length")
            body = fh.read(total - 12)
            trailer = fh.read(4)
            if len(body) != total - 12 or len(trailer) != 4 or struct.unpack(end + "I", trailer)[0] != total:
                raise ValueError("truncated or inconsistent pcapng block")
            name = NG_BLOCKS.get(block_type)
            if name is None:
                info.unknown["0x%08x" % block_type] += 1
                info.blocks["unknown"] += 1
                continue
            info.blocks[name] += 1
            if name in NG_NOT_DECODED:
                info.not_decoded["0x%08x %s" % (block_type, name)] += 1
                continue
            if name == "interface_description":
                if len(body) < 8:
                    raise ValueError("pcapng interface description is shorter than its fixed part")
                link, _res, snap = struct.unpack(end + "HHI", body[:8])
                row = {"section": max(info.sections - 1, 0), "interface": len(local), "link_type": LINKTYPES.get(link, str(link)),
                       "link_type_id": link, "snap_length": snap or None, "packets": 0, "bytes_original": 0,
                       "bytes_captured": 0, "options_malformed": 0}
                opts = ng_options(body, 8, end, info, row)
                resolution = opts.get(9, [b"\x06"])[0][:1] or b"\x06"
                row["ticks_per_second"], row["digits"] = resolution_of(resolution[0])
                row["time_offset_seconds"] = 0
                if opts.get(14) and len(opts[14][0]) == 8:
                    row["time_offset_seconds"] = struct.unpack(end + "q", opts[14][0])[0]
                for code, label in ((2, "name"), (3, "description"), (12, "os")):
                    if opts.get(code):
                        row[label] = text_of(opts[code][0])
                if opts.get(11) and opts[11][0]:
                    kind, payload = opts[11][0][0], opts[11][0][1:]
                    row["capture_filter"] = text_of(payload) if kind == 0 else "a compiled filter program (%d bytes)" % len(payload)
                local[len(local)] = len(info.interfaces)
                info.interfaces.append(row)
            elif name == "interface_statistics":
                if len(body) < 12:
                    raise ValueError("pcapng interface statistics block is shorter than its fixed part")
                iface = struct.unpack(end + "I", body[:4])[0]
                row = {"section": max(info.sections - 1, 0), "interface": iface, "options_malformed": 0}
                high, low = struct.unpack(end + "II", body[4:12])
                if iface in local:
                    istats = info.interfaces[local[iface]]
                    when = (((high << 32) | low) * 1_000_000_000 // istats["ticks_per_second"]) + istats["time_offset_seconds"] * 1_000_000_000
                    row["time_utc"] = fmt_ns(when, istats["digits"])
                    row["time_raw"] = {"ticks": (high << 32) | low, "ticks_per_second": istats["ticks_per_second"]}
                opts = ng_options(body, 12, end, info, row)
                for code, label in ((4, "packets_received"), (5, "packets_dropped_by_interface"), (6, "packets_accepted_by_filter"),
                                    (7, "packets_dropped_by_os"), (8, "packets_delivered_to_user")):
                    if opts.get(code) and len(opts[code][0]) == 8:
                        row[label] = struct.unpack(end + "Q", opts[code][0])[0]
                info.stats.append(row)
            elif name in ("enhanced_packet", "packet_obsolete"):
                if len(body) < 20:
                    raise ValueError("pcapng packet block is shorter than its fixed part")
                if name == "enhanced_packet":
                    iface, high, low, incl, orig = struct.unpack(end + "IIIII", body[:20])
                else:
                    iface, _drops, high, low, incl, orig = struct.unpack(end + "HHIIII", body[:20])
                if iface not in local or 20 + incl > len(body):
                    raise ValueError("pcapng packet names an invalid interface or length")
                index = local[iface]
                row = info.interfaces[index]
                tps = row["ticks_per_second"]
                ticks = (high << 32) | low
                if name == "enhanced_packet" and len(body) > 20 + ((incl + 3) & ~3):
                    packet_opts = ng_options(body, 20 + ((incl + 3) & ~3), end, info, row)
                    if packet_opts.get(4) and len(packet_opts[4][0]) == 8:
                        row["epb_dropcount_total"] = row.get("epb_dropcount_total", 0) + struct.unpack(end + "Q", packet_opts[4][0])[0]
                yield (ticks * 1_000_000_000 // tps + row["time_offset_seconds"] * 1_000_000_000, body[20:20 + incl], orig,
                       index, (ticks, tps, row["time_offset_seconds"]))
            elif name == "simple_packet":
                if not local:
                    raise ValueError("pcapng simple packet block appears before an interface")
                if len(body) < 4:
                    raise ValueError("pcapng simple packet block is shorter than its fixed part")
                orig = struct.unpack(end + "I", body[:4])[0]
                index = local[0]
                snap = info.interfaces[index]["snap_length"]
                captured = min(orig, snap) if snap else orig
                padded = (captured + 3) & ~3
                if len(body) - 4 != padded:
                    raise ValueError("pcapng simple packet block has an inconsistent captured length")
                yield None, body[4:4 + captured], orig, index, None
    return packets


# --- one packet ----------------------------------------------------------------------------------------------

def dissect(body, link):
    """Addresses, protocol, ports and what a TCP packet says, or None when it is not IP (or too short to tell)."""
    if link == 1:
        if len(body) < 14:
            return None
        kind = struct.unpack(">H", body[12:14])[0]
        at = 14
        while kind in (0x8100, 0x88a8, 0x9100) and len(body) >= at + 4:
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

    nonfirst = False
    if kind == 0x0800:
        if len(body) < at + 20:
            return None
        ihl = (body[at] & 0x0F) * 4
        if ihl < 20 or len(body) < at + ihl:
            return None
        protocol = body[at + 9]
        src, dst = address(body[at + 12:at + 16]), address(body[at + 16:at + 20])
        transport = at + ihl
        total = struct.unpack(">H", body[at + 2:at + 4])[0]
        # A total length of zero is what segmentation offload leaves; below the header it is nonsense. Either way
        # the captured bytes are all there is to go on.
        l3_end = at + total if total >= ihl else len(body)
        fragment = struct.unpack(">H", body[at + 6:at + 8])[0]
        if fragment & 0x1fff:
            transport = len(body)
            nonfirst = True
        six = False
    elif kind == 0x86dd:
        if len(body) < at + 40:
            return None
        protocol = body[at + 6]
        src, dst = address(body[at + 8:at + 24], True), address(body[at + 24:at + 40], True)
        transport = at + 40
        length = struct.unpack(">H", body[at + 4:at + 6])[0]
        l3_end = at + 40 + length if length else len(body)
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
                    nonfirst = True
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

    limit = min(len(body), l3_end)
    sport = dport = None
    flags = seq = None
    payload = 0
    headers_complete = False
    if protocol in (6, 17) and not nonfirst and len(body) >= transport + 4:
        sport, dport = struct.unpack(">HH", body[transport:transport + 4])
        if protocol == 6:
            if len(body) >= transport + 14:
                flags = body[transport + 13]
                seq = struct.unpack(">I", body[transport + 4:transport + 8])[0]
                header = (body[transport + 12] >> 4) * 4
                if header >= 20 and len(body) >= transport + header:
                    headers_complete = True
                    payload = max(0, limit - (transport + header))
        else:
            if len(body) >= transport + 8:
                headers_complete = True
                payload = max(0, limit - (transport + 8))
    return {"src": src, "dst": dst, "protocol": PROTOCOLS.get(protocol, str(protocol)),
            "sport": sport, "dport": dport, "flags": flags, "seq": seq, "six": six,
            "headers_complete": headers_complete, "payload": payload, "nonfirst_fragment": nonfirst}


# --- aggregates, in memory and past a cap on disk ----------------------------------------------------------------

class Spill:
    """A SQLite file the aggregates are merged into when memory would otherwise follow the capture."""

    def __init__(self, directory):
        self.directory = directory
        self.path = None
        self.db = None
        self.tables = set()

    def open(self):
        if self.db is not None:
            return
        try:
            if self.directory:
                Path(self.directory).mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(prefix=".pcap_summary-spill-", suffix=".sqlite", dir=self.directory or None)
            os.close(fd)
            self.path = name
            self.db = sqlite3.connect(name, isolation_level=None)
            self.db.execute("PRAGMA journal_mode=OFF")
            self.db.execute("PRAGMA synchronous=OFF")
        except (OSError, sqlite3.Error) as exc:
            fail("the aggregates grew past max_memory_tuples and there is nowhere to keep them (%s); give out_dir, a directory under work/ "
                 "(in a job, under $OUT), or raise max_memory_tuples" % describe(exc))

    def table(self, name):
        self.open()
        if name not in self.tables:
            self.db.execute("CREATE TABLE IF NOT EXISTS %s (k TEXT PRIMARY KEY, sk INTEGER NOT NULL, v TEXT NOT NULL)" % name)
            self.tables.add(name)

    def close(self):
        if self.db is not None:
            try:
                self.db.close()
            except sqlite3.Error:
                pass
            self.db = None
        if self.path:
            for suffix in ("", "-journal", "-wal", "-shm"):
                try:
                    os.unlink(self.path + suffix)
                except OSError:
                    pass
            self.path = None


class Table:
    """key -> record. Merged into the spill file when more than `cap` keys are held; read back sorted by
    (sort key descending, key text) so the order does not depend on whether anything was spilled."""

    def __init__(self, name, cap, spill, merge, sort_of, encode, decode):
        self.name, self.cap, self.spill = name, cap, spill
        self.merge, self.sort_of, self.encode, self.decode = merge, sort_of, encode, decode
        self.mem = {}
        self.spilled = False

    def get(self, key, make):
        rec = self.mem.get(key)
        if rec is None:
            rec = self.mem[key] = make()
            if len(self.mem) > self.cap:
                self.flush(keep=key)
        return rec

    def flush(self, keep=None):
        self.spill.table(self.name)
        self.spilled = True
        db = self.spill.db
        db.execute("BEGIN")
        for key, rec in self.mem.items():
            if key == keep:
                continue
            text = json.dumps(key)
            row = db.execute("SELECT v FROM %s WHERE k = ?" % self.name, (text,)).fetchone()
            if row is not None:
                self.merge(rec, self.decode(json.loads(row[0])))
            db.execute("INSERT OR REPLACE INTO %s (k, sk, v) VALUES (?, ?, ?)" % self.name,
                       (text, self.sort_of(rec), json.dumps(self.encode(rec))))
        db.execute("COMMIT")
        kept = self.mem.get(keep) if keep is not None else None
        self.mem.clear()
        if keep is not None:
            self.mem[keep] = kept

    def rows(self):
        """Every (key, record) in order."""
        if not self.spilled:
            for key, rec in sorted(self.mem.items(), key=lambda kv: (-self.sort_of(kv[1]), json.dumps(kv[0]))):
                yield key, rec
            return
        self.flush()
        cursor = self.spill.db.execute("SELECT k, v FROM %s ORDER BY sk DESC, k" % self.name)
        for text, value in cursor:
            yield tuple(json.loads(text)), self.decode(json.loads(value))


# A tuple record: [packets, bytes_original, bytes_captured, a2b_original, b2a_original, a2b_captured, b2a_captured,
#                  first_ns, last_ns, syn_a, syn_b, synack_a, synack_b, fin, rst, syns{key: [[first, last, n], ...]},
#                  first_raw, last_raw, tuples, syns_not_kept, syn_events, service_port_bases]
# A SYN sent again with the same sequence number within SYN_WINDOW_NS of the FIRST one of its event is the same SYN event
# (a retransmission) and is folded into it, with its count; after that a SYN with that number starts a new event. A row keeps at most
# MAX_SYN_EVENTS events: SYNs past that are counted in syns_not_kept and their times are not kept.
P, BO, BC, ABO, BAO, ABC, BAC, FIRST, LAST, SYNA, SYNB, SAA, SAB, FIN, RST, SYNS, FRAW, LRAW, TUPLES, SYNOVER, SYNEV, BASES = range(22)
COUNTED = (P, BO, BC, ABO, BAO, ABC, BAC, SYNA, SYNB, SAA, SAB, FIN, RST, TUPLES, SYNOVER)
SYN_WINDOW_NS = 120 * 1_000_000_000
MAX_SYN_EVENTS = 10_000
SYN_INLINE = 100        # SYN times shown on a row inline; the whole list is in syn_times_file (and the TSV)


def new_record():
    return [0, 0, 0, 0, 0, 0, 0, None, None, 0, 0, 0, 0, 0, 0, {}, None, None, 0, 0, 0, set()]


def fold_events(events):
    """Events of one (sender, sequence number): sorted by time, those within the window of the one before folded together."""
    timed = sorted((e for e in events if e[0] is not None), key=lambda e: e[0])
    untimed = [e for e in events if e[0] is None]
    out = []
    for e in timed:
        if out and max(out[-1][1], e[1]) - out[-1][0] <= SYN_WINDOW_NS:
            out[-1] = [out[-1][0], max(out[-1][1], e[1]), out[-1][2] + e[2]]
        else:
            out.append(list(e))
    if untimed:
        out.append([None, None, sum(e[2] for e in untimed)])
    return out


def add_syn(rec, key, when):
    """Count one SYN observation of `key` (sender, sequence number) at `when` (ns, or None for a packet with no time)."""
    events = rec[SYNS].get(key)
    if events is not None:
        for e in reversed(events):
            if when is None and e[0] is None:
                e[2] += 1
                return
            if when is not None and e[0] is not None and max(e[1], when) - min(e[0], when) <= SYN_WINDOW_NS:
                e[0], e[1] = min(e[0], when), max(e[1], when)
                e[2] += 1
                return
    if rec[SYNEV] >= MAX_SYN_EVENTS:
        rec[SYNOVER] += 1
        return
    rec[SYNS].setdefault(key, []).append([when, when, 1])
    rec[SYNEV] += 1


def syn_events(rec):
    return [e for events in rec[SYNS].values() for e in events]


def new_port():
    return [0]


def new_talker():
    return [0, 0, 0]


def earlier(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a if a[0] <= b[0] else b


def later(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a if a[0] >= b[0] else b


def merge_record(dst, src):
    for i in COUNTED:
        dst[i] += src[i]
    dst[FRAW], dst[LRAW] = earlier(dst[FRAW], src[FRAW]), later(dst[LRAW], src[LRAW])
    dst[FIRST] = dst[FRAW][0] if dst[FRAW] else None
    dst[LAST] = dst[LRAW][0] if dst[LRAW] else None
    for k, events in src[SYNS].items():
        dst[SYNS][k] = fold_events(dst[SYNS].get(k, []) + events)
    dst[BASES] |= src[BASES]
    kept = sum(len(v) for v in dst[SYNS].values())
    while kept > MAX_SYN_EVENTS:
        # merging two halves can hold more events than a row may keep: the last ones go, counted
        key = next(reversed(dst[SYNS]))
        extra = kept - MAX_SYN_EVENTS
        events = dst[SYNS][key]
        dropped = events[len(events) - min(extra, len(events)):]
        del events[len(events) - len(dropped):]
        dst[SYNOVER] += sum(e[2] for e in dropped)
        if not events:
            del dst[SYNS][key]
        kept -= len(dropped)
    dst[SYNEV] = kept


def encode_record(rec):
    out = list(rec)
    out[SYNS] = [list(k) + [events] for k, events in rec[SYNS].items()]
    out[BASES] = sorted(rec[BASES])
    return out


def decode_record(value):
    rec = list(value)
    rec[SYNS] = {tuple(item[:-1]): item[-1] for item in value[SYNS]}
    rec[BASES] = set(value[BASES])
    rec[FRAW] = tuple(value[FRAW]) if value[FRAW] else None
    rec[LRAW] = tuple(value[LRAW]) if value[LRAW] else None
    return rec


def merge_counts(dst, src):
    for i in range(len(dst)):
        dst[i] += src[i]


def service_of(key, rec):
    """The service port of a tuple and where that came from: a handshake in the capture, else a guess."""
    a, a_port, b, b_port, protocol = key
    if protocol == "TCP":
        if rec[SYNA] and not rec[SYNB]:
            return b_port, "syn_destination"
        if rec[SYNB] and not rec[SYNA]:
            return a_port, "syn_destination"
        if rec[SYNA] and rec[SYNB]:
            return None, "undetermined: a SYN was seen from both ends"
        if rec[SAB] and not rec[SAA]:
            return b_port, "synack_source"
        if rec[SAA] and not rec[SAB]:
            return a_port, "synack_source"
    if a_port > 0 and b_port > 0:
        return min(a_port, b_port), "smaller_port_guess: no handshake for this tuple in the capture"
    return None, "no ports"


def counters_of(rec, digits, with_syn_times):
    events = syn_events(rec)
    row = {"packets": rec[P], "bytes_original": rec[BO], "bytes_captured": rec[BC],
           "a_to_b_bytes_original": rec[ABO], "b_to_a_bytes_original": rec[BAO],
           "a_to_b_bytes_captured": rec[ABC], "b_to_a_bytes_captured": rec[BAC],
           "first": fmt_ns(rec[FIRST], digits), "last": fmt_ns(rec[LAST], digits),
           "syn_observations": rec[SYNA] + rec[SYNB], "syn_unique": len(events),
           "syn_folded": sum(e[2] - 1 for e in events),
           "synack_observations": rec[SAA] + rec[SAB], "fin_observations": rec[FIN], "rst_observations": rec[RST]}
    row["syn_events_not_kept"] = rec[SYNOVER]
    row["syn_unique_is_lower_bound"] = rec[SYNOVER] > 0
    if rec[SYNA] and not rec[SYNB]:
        row["syn_sender"] = "a"
    elif rec[SYNB] and not rec[SYNA]:
        row["syn_sender"] = "b"
    elif rec[SYNA] and rec[SYNB]:
        row["syn_sender"] = "both"
    else:
        row["syn_sender"] = None
    if with_syn_times:
        row["syn_times"] = [fmt_ns(ns, digits) for ns in sorted(e[0] for e in events if e[0] is not None)]
        row["syn_without_time"] = sum(1 for e in events if e[0] is None)
    return row


def tuple_row(key, rec, digits, with_syn_times):
    a, a_port, b, b_port, protocol = key
    return {"a": a, "a_port": a_port if a_port >= 0 else None, "b": b, "b_port": b_port if b_port >= 0 else None,
            "protocol": protocol, **counters_of(rec, digits, with_syn_times)}


BASIS_ORDER = ("syn_destination", "synack_source", "undetermined", "smaller_port_guess", "no ports")


def strongest_basis(bases):
    for name in BASIS_ORDER:
        for basis in sorted(bases):
            if basis.startswith(name):
                return basis
    return sorted(bases)[0] if bases else None


def endpoint_row(key, rec, digits, with_syn_times):
    a, b, protocol, port = key
    return {"a": a, "b": b, "protocol": protocol, "service_port": port if port >= 0 else None,
            "service_port_basis": strongest_basis(rec[BASES]), "service_port_bases": sorted(rec[BASES]),
            "tuples": rec[TUPLES], **counters_of(rec, digits, with_syn_times)}


def endpoint_of(key, rec):
    """The endpoint-aggregate key and record a tuple contributes to: addresses sorted, directions pointed at them,
    and a SYN identified by its sender's port as well, so two clients that happen to use one sequence number stay two."""
    a, a_port, b, b_port, protocol = key
    port, basis = service_of(key, rec)
    swap = a > b
    lo, hi = (b, a) if swap else (a, b)
    out = new_record()
    out[P], out[BO], out[BC] = rec[P], rec[BO], rec[BC]
    if swap:
        out[ABO], out[BAO], out[ABC], out[BAC] = rec[BAO], rec[ABO], rec[BAC], rec[ABC]
        out[SYNA], out[SYNB], out[SAA], out[SAB] = rec[SYNB], rec[SYNA], rec[SAB], rec[SAA]
    else:
        out[ABO], out[BAO], out[ABC], out[BAC] = rec[ABO], rec[BAO], rec[ABC], rec[BAC]
        out[SYNA], out[SYNB], out[SAA], out[SAB] = rec[SYNA], rec[SYNB], rec[SAA], rec[SAB]
    out[FIN], out[RST] = rec[FIN], rec[RST]
    out[FIRST], out[LAST], out[FRAW], out[LRAW] = rec[FIRST], rec[LAST], rec[FRAW], rec[LRAW]
    for (side, seq), events in rec[SYNS].items():
        sender_port = a_port if side == "a" else b_port
        out[SYNS][("a" if (side == "a") != swap else "b", seq, sender_port)] = [list(e) for e in events]
    out[SYNEV], out[SYNOVER] = rec[SYNEV], rec[SYNOVER]
    out[BASES] = {basis}
    out[TUPLES] = 1
    return (lo, hi, protocol, port if port is not None else -1), out


def tsv_cell(value):
    if isinstance(value, list):
        value = json.dumps(value, separators=(",", ":"))
    return ("" if value is None else str(value)).replace("\\", "\\\\").replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n")


def raw_time(raw):
    if raw is None:
        return None
    ticks, tps, offset = raw
    return {"ticks": ticks, "ticks_per_second": tps, "offset_seconds": offset}


def main():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a .pcap or .pcapng file")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    top = args.get("top", DEFAULT_TOP)
    if isinstance(top, bool) or not isinstance(top, int) or top < 1:
        fail("top must be a positive integer")
    if "max_packets" in args:
        fail("max_packets is not supported: a forensic summary must read the whole capture")
    out_dir = args.get("out_dir")
    if out_dir is not None and (not isinstance(out_dir, str) or not out_dir):
        fail("out_dir must be a non-empty string")
    if out_dir is not None:
        out_dir = resolve_output(out_dir, "out_dir")
        try:
            if os.path.exists(out_dir) and os.listdir(out_dir):
                fail("out_dir already holds files", out_dir=out_dir)
        except OSError as exc:
            fail("out_dir cannot be listed (%s)" % describe(exc), out_dir=out_dir)
    only_host = args.get("host")
    wanted_host = None
    if only_host is not None:
        if not isinstance(only_host, str):
            fail("host must be an IP address")
        wanted_host = normal_host(only_host)
        if wanted_host is None:
            fail("host is not an IPv4 or IPv6 address, so no packet can be matched to it", host=only_host)
    only_port = args.get("port")
    if only_port is not None and (isinstance(only_port, bool) or not isinstance(only_port, int) or not 0 <= only_port <= 65535):
        fail("port must be an integer from 0 to 65535")
    grouping_arg = str(args.get("group") or "tuple").lower()
    if grouping_arg not in ("tuple", "session", "endpoint"):
        fail("group must be tuple (the default; session is the old name for it) or endpoint", group=args.get("group"))
    grouping = "endpoint" if grouping_arg == "endpoint" else "tuple"
    with_syn_times = args.get("with_syn_times", args.get("with_starts", False))
    if not isinstance(with_syn_times, bool):
        fail("with_syn_times must be true or false")
    cap = args.get("max_memory_tuples", DEFAULT_MAX_MEMORY_TUPLES)
    if isinstance(cap, bool) or not isinstance(cap, int) or cap < 1:
        fail("max_memory_tuples must be a positive integer")

    spill_dir = out_dir if out_dir else (os.path.join(os.environ["OUT"], "tool-output") if in_job() else None)
    spill = Spill(spill_dir)
    CLEANUP.append(spill.close)       # on every way out: a refused run, a cut-off capture, a signal
    state = {"packets": 0}
    info = Info()
    tuples = Table("tuples", cap, spill, merge_record, lambda r: r[BO], encode_record, decode_record)
    talkers = Table("talkers", cap, spill, merge_counts, lambda r: r[1], list, list)
    ports = Table("ports", cap, spill, merge_counts, lambda r: r[0], list, list)
    by_protocol = collections.Counter()
    truncated_by_protocol = collections.Counter()
    undissected_by_link = collections.Counter()
    first = last = None
    totals = {"bo": 0, "bc": 0, "payload": 0, "with_payload": 0, "cut_packets": 0, "cut_bytes": 0, "within_headers": 0,
              "undissected_cut": 0, "inconsistent": 0, "untimed": 0, "nonfirst": 0, "matching": 0}

    try:
        with open(path, "rb") as fh:
            try:
                packets = read_classic(fh, info)
            except ValueError:
                info.interfaces.clear()
                try:
                    packets = read_pcapng(fh, info)
                except (ValueError, struct.error) as exc:
                    fail("this is neither a classic pcap nor a pcapng", path=path, reason=str(exc))
            try:
                for when, body, orig, index, raw in packets():
                    state["packets"] += 1
                    iface = info.interfaces[index]
                    iface["packets"] += 1
                    iface["bytes_original"] += orig
                    iface["bytes_captured"] += len(body)
                    totals["bo"] += orig
                    totals["bc"] += len(body)
                    if when is None:
                        totals["untimed"] += 1
                    else:
                        if first is None or when < first[0]:
                            first = (when, raw)
                        if last is None or when > last[0]:
                            last = (when, raw)
                    cut = len(body) < orig
                    if len(body) > orig:
                        totals["inconsistent"] += 1
                    if cut:
                        totals["cut_packets"] += 1
                        totals["cut_bytes"] += orig - len(body)
                    found = dissect(body, iface["link_type_id"])
                    if not found:
                        undissected_by_link[iface["link_type"]] += 1
                        if cut:
                            totals["undissected_cut"] += 1
                        continue
                    if cut:
                        truncated_by_protocol[found["protocol"]] += 1
                        if not found["headers_complete"]:
                            totals["within_headers"] += 1
                    if found["nonfirst_fragment"]:
                        totals["nonfirst"] += 1
                    if found["payload"]:
                        totals["payload"] += found["payload"]
                        totals["with_payload"] += 1
                    if wanted_host and wanted_host not in (found["src"], found["dst"]):
                        continue
                    if only_port is not None and only_port not in (found["sport"], found["dport"]):
                        continue
                    totals["matching"] += 1
                    by_protocol[found["protocol"]] += 1
                    if found["dport"] is not None:
                        ports.get((found["dport"],), new_port)[0] += 1
                    t = talkers.get((found["src"],), new_talker)
                    t[0] += 1
                    t[1] += orig
                    t[2] += len(body)
                    sport = found["sport"] if found["sport"] is not None else -1
                    dport = found["dport"] if found["dport"] is not None else -1
                    ends = sorted([(found["src"], sport), (found["dst"], dport)])
                    key = (ends[0][0], ends[0][1], ends[1][0], ends[1][1], found["protocol"])
                    rec = tuples.get(key, new_record)
                    from_a = (found["src"], sport) == ends[0]
                    rec[P] += 1
                    rec[BO] += orig
                    rec[BC] += len(body)
                    if from_a:
                        rec[ABO] += orig
                        rec[ABC] += len(body)
                    else:
                        rec[BAO] += orig
                        rec[BAC] += len(body)
                    if when is not None:
                        if rec[FRAW] is None or when < rec[FRAW][0]:
                            rec[FRAW], rec[FIRST] = (when, raw), when
                        if rec[LRAW] is None or when > rec[LRAW][0]:
                            rec[LRAW], rec[LAST] = (when, raw), when
                    flags = found["flags"]
                    if flags is not None:
                        if flags & 0x12 == 0x02:
                            rec[SYNA if from_a else SYNB] += 1
                            if found["seq"] is not None:
                                add_syn(rec, ("a" if from_a else "b", found["seq"]), when)
                        elif flags & 0x12 == 0x12:
                            rec[SAA if from_a else SAB] += 1
                        if flags & 0x01:
                            rec[FIN] += 1
                        if flags & 0x04:
                            rec[RST] += 1
            except (ValueError, struct.error) as exc:
                fail("capture ended malformed or truncated", path=path, reason=str(exc),
                     packets_read=state["packets"], bytes_consumed=fh.tell(),
                     note="Nothing past this point was read, and the packets before it are not summarised: a summary of part of a "
                          "capture would read as the whole.")
    except OSError as exc:
        fail("the capture could not be read (%s)" % describe(exc), path=path)
    except sqlite3.Error as exc:
        fail("the temporary aggregate file failed (%s)" % describe(exc), out_dir=out_dir)

    digits = max([i.get("digits", 6) for i in info.interfaces] or [6])
    conversations_name = "endpoint_aggregates" if grouping == "endpoint" else "tuple_conversations"
    rows_page = LosslessPage(conversations_name, top)
    talker_page = LosslessPage("top_talkers", top)
    port_page = LosslessPage("top_ports", top)
    syn_page = LosslessPage("syn_times", 0)
    syn_rows_cut = 0
    tsv_path = None
    tsv = None
    try:
        columns = None
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            tsv_path = os.path.join(out_dir, conversations_name + ".tsv")
            tsv = open(tsv_path, "w", encoding="utf-8", newline="\n")
        try:
            if grouping == "endpoint":
                endpoints = Table("endpoints", cap, spill, merge_record, lambda r: r[BO], encode_record, decode_record)
                for key, rec in tuples.rows():
                    ekey, erec = endpoint_of(key, rec)
                    merge_record(endpoints.get(ekey, new_record), erec)
                source = (endpoint_row(k, r, digits, with_syn_times) for k, r in endpoints.rows())
                spilled_here = lambda: tuples.spilled or endpoints.spilled  # noqa: E731
            else:
                source = (tuple_row(k, r, digits, with_syn_times) for k, r in tuples.rows())
                spilled_here = lambda: tuples.spilled  # noqa: E731
            for row in source:
                if tsv is not None:
                    if columns is None:
                        columns = list(row.keys())
                        tsv.write("\t".join(columns) + "\n")
                    tsv.write("\t".join(tsv_cell(row.get(c)) for c in columns) + "\n")
                times = row.get("syn_times")
                if times is not None and len(times) > SYN_INLINE:
                    # the whole list of times goes to a file; the row inline shows the first SYN_INLINE and says how many it left out
                    syn_rows_cut += 1
                    syn_page.add({**{k: row[k] for k in ("a", "b", "a_port", "b_port", "protocol", "service_port", "service_port_basis") if k in row},
                                  "syn_times": times})
                    row = {**row, "syn_times": times[:SYN_INLINE], "syn_times_omitted": len(times) - SYN_INLINE}
                rows_page.add(row)
            if tsv is not None and columns is None:
                tsv.write("a\tb\tprotocol\n")
            for key, rec in talkers.rows():
                talker_page.add({"address": key[0], "packets": rec[0], "bytes_original": rec[1], "bytes_captured": rec[2]})
            for key, rec in ports.rows():
                port_page.add({"port": key[0], "packets": rec[0]})
            spilled = spilled_here() or talkers.spilled or ports.spilled
            pages = {conversations_name: rows_page.finish(), "top_talkers": talker_page.finish(), "top_ports": port_page.finish()}
            syn_times_file = syn_page.finish().get("all_results") if syn_rows_cut else None
        finally:
            if tsv is not None:
                tsv.close()
    except OSError as exc:
        fail("a result could not be written (%s)" % describe(exc), out_dir=out_dir)
    except sqlite3.Error as exc:
        fail("the temporary aggregate file failed (%s)" % describe(exc), out_dir=out_dir)
    finally:
        spill.close()

    unsupported = info.not_decoded + info.unknown
    unsupported_total = sum(unsupported.values())
    notes = []
    if totals["cut_packets"]:
        notes.append("%d packets were captured shorter than they were on the wire (%d bytes cut): their content past the captured "
                     "bytes is not in this file." % (totals["cut_packets"], totals["cut_bytes"]))
    if undissected_by_link:
        notes.append("%d packets were not IP, or used a link type this parser does not decode." % sum(undissected_by_link.values()))
    if unsupported_total:
        notes.append("%d pcapng blocks of types this tool does not decode were counted, not read (unsupported_block_types)." % unsupported_total)
    if info.malformed_options:
        notes.append("%d options declared a length past their block and were not read (malformed_options)." % info.malformed_options)
    if totals["untimed"]:
        notes.append("%d packets (pcapng simple packet blocks) carry no timestamp." % totals["untimed"])
    if totals["inconsistent"]:
        notes.append("%d packet records declare an original length shorter than the bytes captured." % totals["inconsistent"])
    if info.format == "pcap":
        notes.append("A classic pcap holds one interface and no drop counters: whether packets were lost before the file was written is not in it.")
    elif not info.stats:
        notes.append("No interface statistics block is in this pcapng, so the capturing interface's own drop counters are absent: that is not a count of zero.")
    if "with_starts" in args:
        notes.append("with_starts is the old name of with_syn_times; the times are SYN events, not connection starts.")
    if syn_rows_cut:
        notes.append("%d rows hold more than %d SYN times: the first %d are inline and the whole list is in syn_times_file%s."
                     % (syn_rows_cut, SYN_INLINE, SYN_INLINE, " and in the TSV" if tsv_path else ""))
    if any(i.get("epb_dropcount_total") for i in info.interfaces):
        notes.append("Some packet blocks carry a drop count (epb_dropcount_total on the interface): packets the capturing interface dropped just before them.")

    shown_interfaces = [{k: v for k, v in row.items() if k != "digits"} for row in info.interfaces]
    agreeing = {(i["link_type_id"], i["snap_length"]) for i in info.interfaces}
    single = shown_interfaces[0] if len(agreeing) == 1 and shown_interfaces else None

    print(json.dumps({
        "tool": TOOL, "parser": PARSER,
        "path": path, "bytes": os.path.getsize(path), "format": info.format, "version": info.version,
        "link_type": single["link_type"] if single else None,
        "link_type_id": single["link_type_id"] if single else None,
        "snap_length": single["snap_length"] if single else None,
        "interfaces": shown_interfaces,
        "interface_statistics": info.stats,
        "blocks": ({"total": sum(info.blocks.values()), "by_type": dict(info.blocks)} if info.format == "pcapng" else None),
        "unsupported_blocks": unsupported_total,
        "unsupported_block_types": dict(unsupported),
        "malformed_options": info.malformed_options,
        "sections": info.sections if info.format == "pcapng" else None,
        "packets": state["packets"],
        "packets_without_timestamp": totals["untimed"],
        "first_packet": fmt_ns(first[0], digits) if first else None,
        "last_packet": fmt_ns(last[0], digits) if last else None,
        "first_packet_raw": raw_time(first[1]) if first else None,
        "last_packet_raw": raw_time(last[1]) if last else None,
        "duration_ns": (last[0] - first[0]) if first and last else None,
        "duration_seconds": ((last[0] - first[0]) / 1e9) if first and last else None,
        "section_options": info.section_options,
        "bytes_original_total": totals["bo"],
        "bytes_captured_total": totals["bc"],
        "payload_bytes_captured_total": totals["payload"],
        "packets_with_payload_captured": totals["with_payload"],
        "truncation": {"truncated_packets": totals["cut_packets"], "bytes_cut": totals["cut_bytes"],
                       "by_protocol": dict(truncated_by_protocol), "undissected_truncated": totals["undissected_cut"],
                       "truncated_within_headers": totals["within_headers"]},
        "length_inconsistencies": totals["inconsistent"],
        "non_first_fragments": totals["nonfirst"],
        "undissected": {"packets": sum(undissected_by_link.values()), "by_link_type": dict(undissected_by_link)},
        "protocols": dict(by_protocol),
        "filtered": ({"host": wanted_host, "port": only_port, "packets_matching": totals["matching"],
                      "applies_to": "the rows, top_talkers, top_ports, protocols and the SYN counts; NOT to packets, the times, bytes_*_total, the interfaces, "
                                    "truncation, undissected or length_inconsistencies, which are for the whole capture"}
                     if wanted_host or only_port is not None else None),
        "grouping": grouping,
        "group_note": ("session is the old name for tuple: these rows are tuple aggregates, not TCP sessions"
                       if grouping_arg == "session" else None),
        conversations_name: rows_page.page,
        ("endpoint_aggregate_count" if grouping == "endpoint" else "tuple_conversation_count"): rows_page.total,
        conversations_name + "_returned": len(rows_page.page),
        conversations_name + "_omitted": rows_page.total - len(rows_page.page),
        conversations_name + "_tsv": tsv_path,
        "top_talkers": talker_page.page,
        "top_talkers_basis": "per address as the SOURCE of a packet: bytes_original and bytes_captured are what that address sent, not what it received",
        "top_ports": port_page.page,
        "top_ports_basis": "per DESTINATION port of TCP and UDP packets, counted in packets",
        "syn_times_file": syn_times_file,
        "syn_window_seconds": SYN_WINDOW_NS // 1_000_000_000,
        "pages": pages,
        "spilled_to_disk": spilled,
        "max_memory_tuples": cap,
        "notes": notes,
        "note": "Rows are tuple aggregates (a sorted pair of address and port, plus protocol; an endpoint row is a pair of addresses and a "
                "service port), not TCP sessions: a tuple used again later merges with its earlier use. syn_observations counts SYN-only "
                "packets; syn_unique counts SYN events, a SYN sent again with the same sequence number within 120 seconds of the one before "
                "it being folded into it (syn_folded counts those), and a row keeps at most 10,000 events (syn_events_not_kept; then "
                "syn_unique is a lower bound); neither says a handshake completed. bytes_original sums "
                "the original frame length each packet record declares (headers included, retransmissions included) and bytes_captured "
                "the bytes kept; neither is application data delivered. Packet times come from the capturing machine, and nothing in the "
                "file says whether that clock was right: an offset and its drift need several independent matched events and a stated "
                "uncertainty, not one. Persistent TCP, UDP and QUIC traffic has no SYN to count: build an event series from another source.",
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure
        fail("unexpected failure: %s" % describe(exc))
