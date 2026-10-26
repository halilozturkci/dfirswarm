"""The shared scanning engine behind ioc_scan, chunk_needles and sig_carve.

Three tools find literal byte strings in a stream read in blocks, and each used to carry its own loop. They now carry one
engine (the text between the SHARED SCAN markers). These tests hold the three copies equal, hold the engine to a brute-force
search (every position compared with every needle) over every way of cutting a stream into reads, and hold the three tools to
the same answer for the same bytes. The brute force is the definition: a needle occurs wherever the stream's bytes at that
position are the needle's, overlapping occurrences included.
"""
import json
import os
import random
import re
import unittest

from support import Case, PACK_DIR, run_tool, tool_path

BEGIN, END = "# BEGIN SHARED SCAN", "# END SHARED SCAN"


def block_of(name):
    with open(tool_path(name), encoding="utf-8") as fh:
        text = fh.read()
    start, end = text.index(BEGIN), text.index(END)
    assert text.count(BEGIN) == 1, name
    return text[start:end + len(END)]


def engine():
    ns = {}
    exec(block_of("ioc_scan"), ns)
    return ns["StreamScan"]


def brute(stream, needles, start=0, prefix=b""):
    """Every (offset, needle index) the definition gives, where `stream` is the bytes from `start` on and `prefix` the bytes before it:
    a match counts when it ends after `start` and lies wholly inside prefix + stream."""
    whole = prefix + stream
    base = start - len(prefix)
    out = []
    for at in range(len(whole)):
        for vi, nb in enumerate(needles):
            if whole.startswith(nb, at) and base + at + len(nb) > start:
                out.append((base + at, vi))
    return sorted(out)


class Core(unittest.TestCase):
    def test_the_three_tools_carry_the_same_engine_text(self):
        blocks = [block_of(n) for n in ("ioc_scan", "chunk_needles", "sig_carve")]
        self.assertEqual(blocks[0], blocks[1])
        self.assertEqual(blocks[0], blocks[2])
        self.assertGreater(len(blocks[0]), 1500)

    def test_the_engine_finds_what_a_brute_force_search_finds_whatever_the_reads(self):
        StreamScan = engine()
        rng = random.Random(20261013)
        for case in range(1500):
            alphabet = rng.choice([b"ab", b"abc", b"a\x00", b"xyz\x00\x01"])
            stream = bytes(rng.choice(alphabet) for _ in range(rng.randint(0, 120)))
            needles = []
            for _ in range(rng.randint(1, 4)):
                n = bytes(rng.choice(alphabet) for _ in range(rng.randint(1, 6)))
                needles.append(n)
            before, after = rng.choice([(0, 0), (4, 4), (16, 0), (0, 9), (7, 30)])
            want = brute(stream, needles)
            # cut the stream at random places, including empty reads in the middle and one-byte reads
            cuts = sorted(rng.sample(range(len(stream) + 1), min(len(stream) + 1, rng.randint(0, 8))))
            pieces, last = [], 0
            for c in cuts:
                pieces.append(stream[last:c])
                last = c
            pieces.append(stream[last:])
            if rng.random() < 0.3:
                pieces = [stream[i:i + 1] for i in range(len(stream))]
            scan = StreamScan(needles, before=before, after=after)
            got, read = [], 0
            for piece in pieces:
                read += len(piece)
                for at, vi, buf, base in scan.feed(piece):
                    got.append((at, vi))
                    self.assertEqual(buf[at - base:at - base + len(needles[vi])], needles[vi], (case, at))
                    # the context is whole: `before` bytes behind and `after` after, as far as the stream goes
                    lo, hi = max(0, at - before), min(len(stream), at + len(needles[vi]) + after)
                    self.assertEqual(buf[lo - base:hi - base], stream[lo:hi], (case, at, "context"))
            for at, vi, buf, base in scan.feed(b"", final=True):
                got.append((at, vi))
                lo, hi = max(0, at - before), min(len(stream), at + len(needles[vi]) + after)
                self.assertEqual(buf[lo - base:hi - base], stream[lo:hi], (case, at, "context at the end"))
            self.assertEqual(got, want, (case, stream, needles, [len(p) for p in pieces]))

    def test_matches_come_out_in_offset_order_then_needle_order(self):
        StreamScan = engine()
        scan = StreamScan([b"ab", b"a", b"b"], after=2)
        got = [(at, vi) for at, vi, _b, _o in scan.feed(b"abab", final=True)]
        self.assertEqual(got, [(0, 0), (0, 1), (1, 2), (2, 0), (2, 1), (3, 2)])

    def test_a_scan_that_stops_and_one_that_goes_on_from_there_find_what_one_scan_finds(self):
        StreamScan = engine()
        rng = random.Random(7)
        for case in range(800):
            stream = bytes(rng.choice(b"ab") for _ in range(rng.randint(2, 100)))
            needles = [bytes(rng.choice(b"ab") for _ in range(rng.randint(1, 5))) for _ in range(rng.randint(1, 3))]
            cut = rng.randint(1, len(stream) - 1)
            longest = max(len(n) for n in needles)
            first = StreamScan(needles)
            got = []
            for i in range(0, cut, 7):
                got += [(a, v) for a, v, _b, _o in first.feed(stream[i:min(cut, i + 7)])]
            got += [(a, v) for a, v, _b, _o in first.feed(b"", final=True)]        # the scan stopped at `cut`
            carry = stream[max(0, cut - (longest - 1)):cut]
            second = StreamScan(needles, start=cut, prefix=carry)
            for i in range(cut, len(stream), 5):
                got += [(a, v) for a, v, _b, _o in second.feed(stream[i:i + 5])]
            got += [(a, v) for a, v, _b, _o in second.feed(b"", final=True)]
            self.assertEqual(sorted(got), brute(stream, needles), (case, stream, needles, cut))
            self.assertEqual(len(got), len(set(got)), "a match was reported twice across the stop")


class Same(Case):
    """The same bytes, asked of the three tools with different read sizes, give the same offsets."""

    def test_regf_offsets_are_the_same_in_ioc_scan_chunk_needles_and_sig_carve_for_any_read_size(self):
        marker = b"regf"
        data = bytearray(b"\x00" * 700)
        places = list(range(3, 480, 13)) + [0, 650]
        for at in places:
            data[at:at + 4] = marker
        # "regfregf": overlapping and adjacent occurrences
        data[500:508] = marker * 2
        want = sorted(i for i in range(len(data) - 3) if data[i:i + 4] == marker)
        self.assertGreaterEqual(len(want), 38)
        src = self.write("inputs/blob.bin", bytes(data))
        for size in (16, 17, 64, 100, 4096):
            ioc = run_tool("ioc_scan", {"path": src, "needles": ["regf"], "chunk": size, "max_hits": 1000, "unique_only": False}, self.dir)
            self.assertEqual(ioc.code, 0, ioc.stdout)
            ioc_offsets = sorted(h["offset"] for h in ioc.json["hits"] if h["enc"] == "ascii")
            chunk = run_tool("chunk_needles", {"path": src, "needles": "regf", "chunk": size, "max_hits": 1000}, self.dir)
            self.assertEqual(chunk.code, 0, chunk.stdout)
            chunk_offsets = sorted(h["off"] for h in chunk.json["hits"]["regf"]["locations"] if h["enc"] == "ascii")
            sig = run_tool("sig_carve", {"path": src, "sig": "regf", "window_bytes": size, "max_hits": 1000}, self.dir)
            self.assertEqual(sig.code, 0, sig.stdout)
            sig_offsets = sorted(h["offset"] for h in sig.json["signatures"]["regf"]["hits"])
            self.assertEqual(ioc_offsets, want, ("ioc_scan", size))
            self.assertEqual(chunk_offsets, want, ("chunk_needles", size))
            self.assertEqual(sig_offsets, want, ("sig_carve", size))

    def test_a_utf16_needle_is_found_by_ioc_scan_and_chunk_needles_at_the_same_offsets(self):
        text = "password"
        wide = text.encode("utf-16le")
        data = bytearray(b"\x00" * 400)
        for at in (0, 15, 16, 17, 100, 391):
            data[at:at + len(wide)] = wide
        want = sorted(i for i in range(len(data) - len(wide) + 1) if data[i:i + len(wide)] == wide)
        src = self.write("inputs/wide.bin", bytes(data))
        for size in (16, 33, 4096):
            ioc = run_tool("ioc_scan", {"path": src, "needles": [text], "chunk": size, "max_hits": 1000, "unique_only": False}, self.dir)
            chunk = run_tool("chunk_needles", {"path": src, "needles": text, "chunk": size, "max_hits": 1000}, self.dir)
            self.assertEqual(sorted(h["offset"] for h in ioc.json["hits"] if h["enc"] == "utf16"), want, size)
            self.assertEqual(sorted(h["off"] for h in chunk.json["hits"][text]["locations"] if h["enc"] == "utf16le"), want, size)

    def test_the_engine_is_where_each_tool_reads_from(self):
        for name in ("ioc_scan", "chunk_needles", "sig_carve"):
            with open(tool_path(name), encoding="utf-8") as fh:
                text = fh.read()
            code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
            self.assertIn("StreamScan(", code, name)
            self.assertNotIn(".find(", code.replace("buf.find(needle", ""), "%s searches a buffer itself instead of through the engine" % name)


if __name__ == "__main__":
    unittest.main()
