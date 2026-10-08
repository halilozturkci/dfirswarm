"""file_carver: where a candidate ends, and what was checked to say so.

Every fixture is built here from the format's specification (the registry hive
base block and hive bins as Maxim Suhanov's description lays them out, PDF's
cross-reference and incremental-update rules, PNG's chunk CRCs, the JPEG marker
syntax, the GIF block grammar, the PE/COFF headers, ZIP's end record, SQLite's
header), never by running the carver and keeping what it printed. The ZIP and the
SQLite database are made by the standard library's own writers.
"""
import hashlib
import importlib.util
import io
import json
import os
import sqlite3
import struct
import tracemalloc
import unittest
import zipfile
import zlib

from support import Case, run_tool, tool_path


def regf(bins_sizes=(0x1000, 0x2000), good_chain=True, good_checksum=True, bins_total=None):
    """A registry hive: a 4096-byte base block, then hive bins, each starting with its 32-byte header."""
    total = sum(bins_sizes) if bins_total is None else bins_total
    base = bytearray(4096)
    base[0:4] = b"regf"
    struct.pack_into("<II", base, 4, 7, 7)                  # primary and secondary sequence numbers
    struct.pack_into("<IIIII", base, 20, 1, 5, 0, 1, 0x20)  # major, minor, file type, file format, root cell offset
    struct.pack_into("<I", base, 40, total)                 # hive bins data size, at 0x28
    struct.pack_into("<I", base, 44, 1)                     # clustering factor
    x = 0
    for (word,) in struct.iter_unpack("<I", bytes(base[:508])):
        x ^= word
    struct.pack_into("<I", base, 508, x if good_checksum else x ^ 0xFFFF)
    out = bytes(base)
    pos = 0
    for size in bins_sizes:
        hb = bytearray(size)
        hb[0:4] = b"hbin"
        struct.pack_into("<II", hb, 4, pos if good_chain else pos + 8, size)
        out += bytes(hb)
        pos += size
    return out


def pdf_revision_one():
    body = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    xref_at = len(body)
    body += b"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % xref_at
    return body, xref_at


def pdf_two_revisions():
    first, first_xref = pdf_revision_one()
    update = b"2 0 obj\n<< /Type /Note >>\nendobj\n"
    xref2 = len(first) + len(update)
    update += (b"xref\n2 1\n%010d 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n"
               % (len(first), first_xref, xref2))
    return first + update, len(first)


def png(extra_text=b""):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"tEXt", b"Comment\x00" + extra_text) +
            chunk(b"IDAT", zlib.compress(b"\x00\x00")) + chunk(b"IEND", b""))


def jpeg_with_thumbnail():
    thumb = b"\xff\xd8\xff\xdb\x00\x02\xff\xd9"                           # an embedded JPEG: SOI, an empty DQT, EOI
    app1 = b"Exif\x00\x00" + thumb
    def seg(code, payload):
        return bytes([0xFF, code]) + struct.pack(">H", len(payload) + 2) + payload
    sof = seg(0xC0, bytes([8, 0, 1, 0, 1, 1, 1, 0x11, 0]))
    sos = seg(0xDA, bytes([1, 1, 0, 0, 63, 0]))
    scan = b"\x12\xff\x00\x34\xff\xd0\x56"                                # entropy data: a stuffed 0xFF and a restart marker
    return b"\xff\xd8" + seg(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00") + seg(0xE1, app1) + seg(0xDB, bytes(65)) + sof + sos + scan + b"\xff\xd9"


def gif_with_semicolon_in_data():
    header = b"GIF89a" + struct.pack("<HH", 1, 1) + bytes([0x80, 0, 0]) + b"\x00\x00\x00\xff\xff\xff"     # a two-entry global colour table
    image = b"\x2c" + struct.pack("<HHHH", 0, 0, 1, 1) + b"\x00" + b"\x02" + bytes([3]) + b"\x3b\x3b\x3b" + b"\x00"   # the data holds 0x3B bytes
    return header + image + b"\x3b"


def pe(overlay=b"", cert=None, sections=1):
    """A minimal PE32: DOS header, e_lfanew=0x40, COFF header, a 224-byte optional header, section headers; each section's raw data 0x200 at 0x200 + 0x200*i."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x14C, sections, 0, 0, 0, 224, 0x102)
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 60, 0x200)           # SizeOfHeaders
    struct.pack_into("<I", opt, 92, 16)              # NumberOfRvaAndSizes
    if cert:
        struct.pack_into("<II", opt, 96 + 8 * 4, *cert)     # the certificate table: a file offset and a size
    secs = b""
    for i in range(sections):
        secs += (".sec%d" % i).encode().ljust(8, b"\0") + struct.pack("<IIIIIIHHI", 0x200, 0x1000 * (i + 1), 0x200, 0x200 + 0x200 * i, 0, 0, 0, 0, 0x60000020)
    headers = bytes(dos) + coff + bytes(opt) + secs
    image = headers.ljust(0x200, b"\0") + b"".join(bytes([0x41 + i]) * 0x200 for i in range(sections))
    return image + overlay


class FileCarver(Case):
    def carve(self, data, sig, at=0, **kw):
        src = self.write("dump.bin", b"JUNK" * 8 + b"\0" * ((at - 32) if at > 32 else 0) + data + b"\xaa" * 64 + b"\x00" * 4096) if at else self.write("dump.bin", data + b"TRAILING" * 8)
        args = {"path": src, "offset": at, "sig_type": sig}
        args.update(kw)
        return run_tool("file_carver", args, self.dir)

    # --- registry hive -------------------------------------------------------------

    def test_a_hive_is_cut_at_its_base_block_plus_its_hive_bins_size(self):
        data = regf((0x1000, 0x2000))
        r = self.carve(data, "regf", at=4096)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["size"], 4096 + 0x3000)
        self.assertEqual(r.json["boundary"], "validated")
        self.assertEqual(r.json["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(r.json["kind"], "candidate_fragment")

    def test_a_hive_whose_bins_do_not_chain_is_a_heuristic_not_a_validated_size(self):
        r = self.carve(regf((0x1000, 0x2000), good_chain=False), "regf", at=4096)
        self.assertEqual(r.json["size"], 4096 + 0x3000)
        self.assertEqual(r.json["boundary"], "heuristic")
        self.assertTrue(any("hive bin" in n for n in r.json["notes"]))
        bad_sum = self.carve(regf((0x1000,), good_checksum=False), "regf", at=4096)
        self.assertTrue(any("checksum" in n and "NOT" in n for n in bad_sum.json["notes"]), bad_sum.json["notes"])

    def test_a_hive_bins_size_that_is_not_a_multiple_of_a_page_is_refused(self):
        r = self.carve(regf((0x1000,), bins_total=0x1234), "regf", at=4096)
        self.assertEqual(r.code, 1)
        self.assertIn("multiple of 4096", r.json["error"])

    # --- PDF -----------------------------------------------------------------------

    def test_a_pdf_with_an_incremental_update_is_cut_at_the_last_revision(self):
        data, first_len = pdf_two_revisions()
        second_pdf, _ = pdf_revision_one()          # another, unrelated PDF follows in the dump
        src = self.write("dump.bin", b"\0" * 100 + data + b"\0" * 10 + second_pdf)
        r = run_tool("file_carver", {"path": src, "offset": 100, "sig_type": "PDF"}, self.dir)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["size"], len(data))                      # not first_len, where the first %%EOF is
        self.assertGreater(len(data), first_len)
        self.assertEqual(r.json["boundary"], "validated")
        self.assertTrue(any("2 revision" in c for c in r.json["checks"]), r.json["checks"])

    def test_a_pdf_with_no_xref_is_only_a_heuristic(self):
        data = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n"
        r = self.carve(data, "PDF")
        self.assertEqual(r.json["boundary"], "heuristic")
        self.assertEqual(r.json["size"], len(data))

    # --- PE ------------------------------------------------------------------------

    def test_a_pe_with_an_overlay_is_flagged_not_trusted(self):
        image = pe()
        r = self.carve(image + b"OVERLAY-PAYLOAD" * 10, "PE")
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["size"], len(image))                 # the headers' end ...
        self.assertTrue(r.json["overlay_uncertain"])                 # ... and the bytes after it are said to be unknown
        self.assertEqual(r.json["boundary"], "heuristic")

    def test_a_pe_with_a_certificate_table_ends_after_it(self):
        base = pe(sections=1)
        cert_off = len(base)
        cert = b"\x00" * 0x100
        r = self.carve(pe(cert=(cert_off, 0x100), overlay=cert), "PE")
        self.assertEqual(r.json["size"], cert_off + 0x100)

    def test_a_truncated_mz_is_an_error_not_an_exception(self):
        # The source ends where the data does, so a header read past it has nothing to read.
        for data in (b"MZ" + b"\x00" * 38, b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40) + b"PE\x00\x00" + b"\x00" * 4,
                     pe()[:0x40 + 24 + 100]):
            src = self.write("trunc.bin", data)
            r = run_tool("file_carver", {"path": src, "offset": 0, "sig_type": "PE"}, self.dir)
            self.assertEqual(r.code, 1)
            self.assertIn("error", r.json or {})
            self.assertNotIn("Traceback", r.stdout + r.stderr)

    # --- ZIP -----------------------------------------------------------------------

    def test_a_zip_that_holds_a_zip_ends_at_its_own_end_record(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w", zipfile.ZIP_STORED) as z:
            z.writestr("inner.txt", "inner")
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w", zipfile.ZIP_STORED) as z:
            z.writestr("nested.zip", inner.getvalue())          # stored: the inner end record is plain in the outer's data
            z.writestr("tail.txt", "t" * 100)
        data = outer.getvalue()
        self.assertLess(data.find(b"PK\x05\x06"), data.rfind(b"PK\x05\x06"))     # the first end marker is not the outer's
        r = self.carve(data, "ZIP")
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["size"], len(data))
        self.assertEqual(r.json["boundary"], "validated")

    def test_a_zip_whose_directory_offsets_disagree_is_a_heuristic(self):
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as z:
            z.writestr("a.txt", "x")
        data = bytearray(outer.getvalue())
        eocd = data.rfind(b"PK\x05\x06")
        struct.pack_into("<I", data, eocd + 16, 0x1234)             # the directory offset no longer agrees
        r = self.carve(bytes(data), "ZIP")
        self.assertEqual(r.json["boundary"], "heuristic")

    # --- PNG, JPEG, GIF: markers inside the payload --------------------------------

    def test_png_chunks_are_walked_so_an_iend_inside_a_chunk_does_not_end_it(self):
        data = png(extra_text=b"IEND\xaeB`\x82 and more")          # the footer bytes sit inside a tEXt chunk
        r = self.carve(data, "PNG")
        self.assertEqual(r.json["size"], len(data))
        self.assertEqual(r.json["boundary"], "validated")
        broken = bytearray(data)
        broken[20] ^= 0xFF                                           # one byte inside the first chunk
        self.assertEqual(self.carve(bytes(broken), "PNG").code, 1)

    def test_a_jpeg_thumbnail_does_not_end_the_jpeg(self):
        data = jpeg_with_thumbnail()
        self.assertLess(data.find(b"\xff\xd9"), len(data) - 2)       # an EOI appears before the real one
        r = self.carve(data, "JPEG")
        self.assertEqual(r.json["size"], len(data))
        self.assertEqual(r.json["boundary"], "validated")

    def test_a_gif_trailer_byte_inside_the_image_data_does_not_end_the_gif(self):
        data = gif_with_semicolon_in_data()
        self.assertLess(data.find(b"\x3b"), len(data) - 1)
        r = self.carve(data, "GIF")
        self.assertEqual(r.json["size"], len(data))
        self.assertEqual(r.json["boundary"], "validated")

    # --- SQLite --------------------------------------------------------------------

    def test_a_sqlite_database_is_cut_at_page_size_times_page_count(self):
        path = self.path("a.db")
        conn = sqlite3.connect(path)
        conn.executescript("create table t(x); insert into t values (zeroblob(20000));")
        conn.commit()
        conn.close()
        raw = self.read(path, "rb")
        r = self.carve(raw, "SQLite", at=8192)
        self.assertEqual(r.json["size"], len(raw))
        self.assertEqual(r.json["boundary"], "validated")
        # A page size that is not a power of two is no SQLite header.
        broken = bytearray(raw)
        struct.pack_into(">H", broken, 16, 1000)
        self.assertEqual(self.carve(bytes(broken), "SQLite").code, 1)
        # A counter that disagrees with version-valid-for makes the page count a guess.
        guess = bytearray(raw)
        struct.pack_into(">I", guess, 92, 0)
        self.assertEqual(self.carve(bytes(guess), "SQLite").json["boundary"], "heuristic")

    # --- found by review: refusals, windows, counts ----------------------------------

    def test_an_unsupported_type_and_a_missing_signature_are_json_refusals(self):
        src = self.write("a.bin", b"\0" * 64)
        r = run_tool("file_carver", {"path": src, "offset": 0, "sig_type": "ELF"}, self.dir)
        self.assertEqual(r.code, 1)
        self.assertEqual(r.json["sig_type"], "ELF")
        self.assertIn("PNG", r.json["supported"])
        r = run_tool("file_carver", {"path": src, "offset": 0, "sig_type": "PE"}, self.dir)
        self.assertEqual((r.code, r.json["sig_type"]), (1, "PE"))
        self.assertIn("not at the offset", r.json["error"])
        self.assertNotIn("Traceback", r.stderr)

    def test_an_output_that_is_the_run_directory_writes_nothing_anywhere(self):
        run = self.path("run")
        os.makedirs(run)
        src = self.write("run/pic.png", png())
        before = set(os.listdir(self.dir))
        for bad in (".", "work/..", "a\x00b", ["x"], 5):
            r = run_tool("file_carver", {"path": src, "offset": 0, "sig_type": "PNG", "output": bad}, run)
            self.assertEqual(r.code, 1, bad)
            self.assertNotIn("Traceback", r.stderr)
        self.assertEqual(set(os.listdir(self.dir)), before, "something was written beside the run directory")
        self.assertEqual([n for n in os.listdir(run) if n != "pic.png"], [])

    def test_a_pdf_with_very_many_revisions_is_not_called_validated_past_the_cap(self):
        body = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        xref_at = len(body)
        body += b"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % xref_at
        prev = xref_at
        for i in range(1200):
            obj = b"%d 0 obj\n<< >>\nendobj\n" % (i + 2)
            at = len(body) + len(obj)
            body += obj + b"xref\n%d 1\n%010d 00000 n \ntrailer\n<< /Size %d /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n" % (i + 2, len(body), i + 3, prev, at)
            prev = at
        r = self.carve(body, "PDF")
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["boundary"], "heuristic")
        self.assertTrue(any("most this tool takes" in n for n in r.json["notes"]), r.json["notes"])

    def test_a_pdf_whose_window_is_cut_by_max_size_says_a_later_revision_may_lie_beyond(self):
        data, first_len = pdf_two_revisions()
        r = self.carve(data, "PDF", max_size=first_len + 20)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["size"], first_len)
        self.assertEqual(r.json["boundary"], "heuristic")
        self.assertTrue(any("window ended at max_size" in n for n in r.json["notes"]), r.json["notes"])

    def test_a_zip_with_65535_entries_is_validated_and_a_garbage_zip64_locator_is_skipped(self):
        big = io.BytesIO()
        with zipfile.ZipFile(big, "w", zipfile.ZIP_STORED) as z:
            for i in range(65535):
                z.writestr("f%d" % i, b"")
        data = big.getvalue()
        r = self.carve(data, "ZIP")
        self.assertEqual((r.json["size"], r.json["boundary"]), (len(data), "validated"))
        # A stored member that holds a ZIP64 locator with an absurd offset, then an end record that cannot be this archive's.
        decoy = b"PK\x06\x07" + struct.pack("<IQI", 0, 0xFFFFFFFFFFFFFFF0, 1) + b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 1, 1, 0xFFFFFFFF, 0xFFFFFFFF, 0)
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w", zipfile.ZIP_STORED) as z:
            z.writestr("decoy.bin", decoy)
            z.writestr("tail.txt", "t" * 50)
        raw = outer.getvalue()
        r = self.carve(raw, "ZIP")
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual((r.json["size"], r.json["boundary"]), (len(raw), "validated"))

    def test_a_zip_of_65536_entries_is_validated_by_its_zip64_record(self):
        # Python writes a ZIP64 end record and locator once there are more than 65535 entries, with the end record's count at 0xFFFF and
        # its directory size and offset as they are: the plain rule (the directory ends where the end record starts) does not hold, the
        # ZIP64 record's does.
        big = io.BytesIO()
        with zipfile.ZipFile(big, "w", zipfile.ZIP_STORED) as z:
            for i in range(65536):
                z.writestr("f%d" % i, b"")
        data = big.getvalue()
        self.assertEqual(data[-22 - 20 - 56:-22 - 20 - 56 + 4], b"PK\x06\x06")
        r = self.carve(data, "ZIP")
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual((r.json["size"], r.json["boundary"]), (len(data), "validated"))
        self.assertEqual(r.json["boundary_basis"], "ZIP64 end-of-central-directory record")

    def test_a_truncated_jpeg_followed_by_another_ends_where_the_next_begins_and_is_a_guess(self):
        first = jpeg_with_thumbnail()
        truncated = first[:-2 - 30]                          # its EOI and the last of its entropy-coded bytes are gone
        data = truncated + first                              # the next file follows at once
        r = self.carve(data, "JPEG")
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["size"], len(truncated))
        self.assertEqual(r.json["boundary"], "heuristic")
        self.assertIn("start-of-image", json.dumps(r.json))

    # --- the contract --------------------------------------------------------------

    def test_an_existing_output_is_not_overwritten(self):
        data = png()
        src = self.write("dump.bin", data)
        existing = self.write("work/out.bin", b"keep me")
        r = run_tool("file_carver", {"path": src, "offset": 0, "sig_type": "PNG", "output": "work/out.bin"}, self.dir)
        self.assertEqual(r.code, 1)
        self.assertEqual(self.read(existing, "rb"), b"keep me")
        ok = run_tool("file_carver", {"path": src, "offset": 0, "sig_type": "PNG", "output": "work/new.bin"}, self.dir)
        self.assertEqual(ok.code, 0)
        self.assertEqual(self.read("work/new.bin", "rb"), data)
        self.assertEqual([n for n in os.listdir(self.path("work")) if n.startswith(".")], [])

    def test_a_candidate_larger_than_max_size_is_refused_not_cut(self):
        r = self.carve(regf((0x1000, 0x2000)), "regf", at=4096, max_size=5000)
        self.assertEqual(r.code, 1)

    def test_the_source_is_streamed_never_held_whole(self):
        spec = importlib.util.spec_from_file_location("fc", tool_path("file_carver"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # a PNG whose IDAT is 40 MiB must be walked and hashed without being read into memory
        payload = os.urandom(1024) * (40 * 1024)
        def chunk(kind, data):
            return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        bigpng = self.path("big.png")
        with open(bigpng, "wb") as fh:
            fh.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)) + chunk(b"IDAT", payload) + chunk(b"IEND", b""))
        tracemalloc.start()
        got = mod.carve(bigpng, 0, "PNG", 100_000_000)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        self.assertEqual(got["size"], os.path.getsize(bigpng))
        self.assertLess(peak, 20 * 1024 * 1024, "peak %d bytes while carving a 40 MiB PNG" % peak)

    def test_in_a_job_an_output_outside_out_is_refused_and_one_under_it_is_written(self):
        src = self.write("pic.png", png())
        out = self.path("job-out")
        os.makedirs(out)
        env = {"JOB_ID": "j000012", "OUT": out}
        r = run_tool("file_carver", {"path": src, "offset": 0, "sig_type": "PNG", "output": "work/pic.png"}, self.dir, env=env)
        self.assertEqual(r.code, 1, r.stdout)
        self.assertIn("under $OUT", r.json["error"])
        self.assertFalse(os.path.exists(self.path("work")))
        r = run_tool("file_carver", {"path": src, "offset": 0, "sig_type": "PNG", "output": os.path.join(out, "pic.png")}, self.dir, env=env)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(self.read(os.path.join(out, "pic.png"), "rb"), png())


if __name__ == "__main__":
    unittest.main()
