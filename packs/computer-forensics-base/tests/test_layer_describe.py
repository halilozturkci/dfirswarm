"""layer_describe: one immutable descriptor for declared sources, and no reading of anything that was not declared.

The headers are built from the formats' documented layouts (the EWF1 file header and section descriptors, a QCOW2 header with its backing
file name, a VMDK text descriptor, a VHD footer and dynamic header), the programs are stand-ins that print the wording the Sleuth Kit and
qemu-img use, and the real Sleuth Kit is run over an MBR image built here (512- and 4096-byte sectors) when the host has it.
"""
import hashlib
import json
import os
import resource
import signal
import struct
import subprocess
import sys
import time
import unittest
import zlib

from support import CLEAN, Case, have, run_tool, stand_in, tool_path

SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
MMLS_512 = """DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000026623   0000024576   Linux (0x83)
"""
MMLS_4K = MMLS_512.replace("512-byte", "4096-byte")
FSSTAT = "FILE SYSTEM INFORMATION\n--------------------------------------------\nFile System Type: Ext4\nSector Size: 512\nCluster Size: 4096\n"
IMG_STAT = "IMAGE FILE INFORMATION\n--------------------------------------------\nImage Type:\traw\n\nSize in bytes: %d\nSector size:\t512\n"


def descriptor(kind, offset, size):
    body = kind.ljust(16, b"\0") + struct.pack("<QQ", offset if kind in (b"next", b"done") else offset + 76 + size, 76 + size) + b"\0" * 40
    return body + struct.pack("<I", zlib.adler32(body) & 0xFFFFFFFF)


def ewf_segment(number, last):
    out = bytearray(SIGNATURE + b"\x01" + struct.pack("<H", number) + b"\0\0")
    body = b"volume-data" * 4
    out += descriptor(b"volume", len(out), len(body)) + body
    out += descriptor(b"done" if last else b"next", len(out), 0)
    return bytes(out)


def mbr(start, count):
    sector = bytearray(512)
    sector[446 + 4] = 0x83
    struct.pack_into("<II", sector, 446 + 8, start, count)
    sector[510:512] = b"\x55\xaa"
    return bytes(sector)


def qcow2(backing=None, virtual=1 << 20):
    head = bytearray(104)
    head[0:4] = b"QFI\xfb"
    struct.pack_into(">I", head, 4, 2)
    name = backing.encode() if backing else b""
    if backing:
        struct.pack_into(">QI", head, 8, 104, len(name))
    struct.pack_into(">I", head, 20, 16)
    struct.pack_into(">Q", head, 24, virtual)
    return bytes(head) + name + b"\0" * 4096


def vmdk_text(parent=None, extent="disk-flat.vmdk"):
    lines = ["# Disk DescriptorFile", "version=1", "CID=fffffffe", "parentCID=%s" % ("12345678" if parent else "ffffffff"), 'createType="monolithicFlat"', ""]
    if parent:
        lines.insert(4, 'parentFileNameHint="%s"' % parent)
    lines += ["# Extent description", 'RW 2048 FLAT "%s" 0' % extent, ""]
    return "\n".join(lines).encode()


def vhd_footer(disk_type, size=1 << 20, data_offset=0xFFFFFFFFFFFFFFFF):
    footer = bytearray(512)
    footer[0:8] = b"conectix"
    struct.pack_into(">Q", footer, 16, data_offset)
    struct.pack_into(">Q", footer, 48, size)
    struct.pack_into(">I", footer, 60, disk_type)
    return bytes(footer)


def vhd_differencing(parent):
    header = bytearray(1024)
    header[0:8] = b"cxsparse"
    name = parent.encode("utf-16-be")
    header[64:64 + len(name)] = name
    return vhd_footer(4, data_offset=512) + bytes(header) + vhd_footer(4)


class LayerDescribe(Case):
    def tools(self, mmls=MMLS_512, qemu=None, log=None, img_type="raw", img_size=None):
        d = self.path("bin")
        os.makedirs(d, exist_ok=True)
        rec = lambda name: ('echo "%s $@" >> %s\n' % (name, log)) if log else ""
        stand_in(d, "mmls", rec("mmls") + "cat <<'EOF'\n%sEOF\n" % mmls)
        stand_in(d, "fsstat", rec("fsstat") + "cat <<'EOF'\n%sEOF\n" % FSSTAT)
        sizes = 'total=0; for a; do if [ -f "$a" ]; then total=$((total + $(wc -c < "$a"))); fi; done\n'
        if img_size is not None:
            sizes = "total=%d" % img_size + chr(10)
        stand_in(d, "img_stat", rec("img_stat") + sizes + 'printf "IMAGE FILE INFORMATION\\n-----\\nImage Type:\\t%s\\n\\nSize in bytes: %s\\n" "' + img_type + '" "$total"\n')
        stand_in(d, "ewfinfo", rec("ewfinfo") + "echo 'ewfinfo stand-in'; exit 1\n")
        stand_in(d, "qemu-img", rec("qemu-img") + ("cat <<'EOF'\n%s\nEOF\n" % qemu if qemu else "exit 1\n"))
        return d

    def run_it(self, sources, path_dirs=None, **extra):
        args = dict(extra, sources=sources)
        args.setdefault("out_dir", self.path("out", "layers"))
        return run_tool("layer_describe", args, self.dir, path_dirs=path_dirs if path_dirs is not None else [self.tools()])

    def raw(self, name="evidence/disk.001", size=1 << 20, head=b""):
        return self.write(name, (head + b"\0" * size)[:size])

    # ---- the descriptor
    def test_a_split_raw_set_of_three_segments_is_one_media_and_its_descriptor_is_named_by_its_hash(self):
        parts = [self.raw("evidence/d.00%d" % n, size=1 << 20, head=mbr(2048, 24576) if n == 1 else b"") for n in (1, 2, 3)]
        res = self.run_it(parts)
        self.assertEqual(res.code, 0, res.stderr)
        a = res.json
        self.assertEqual((a["container"]["layer"], a["media"]["bytes"], a["status"]), ("split_raw", 3 << 20, CLEAN), a["status_basis"])
        self.assertEqual([s["index"] for s in a["sources"]], [0, 1, 2])
        name = a["descriptor"]["file"]
        path = self.path("out", "layers", name)
        with open(path, "rb") as fh:
            body = fh.read()
        self.assertEqual(name, "layer-%s.json" % hashlib.sha256(body).hexdigest())
        self.assertEqual(a["descriptor"]["sha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
        d = json.loads(body)
        self.assertEqual([s["offset_in_media"] for s in d["sources"]], [0, 1 << 20, 2 << 20])
        self.assertEqual(d["sector_size"], 512)
        self.assertEqual(d["partitions"][-1]["offset_sectors"], 2048)
        self.assertEqual(d["partitions"][-1]["filesystem"]["fs_type"], "Ext4")
        self.assertNotIn("backing-chain", " ".join(json.dumps(p["argv"]) for p in d["programs"]))

    def test_a_second_call_with_the_same_inputs_gives_the_same_bytes_and_replaces_nothing(self):
        parts = [self.raw("evidence/d.001"), self.raw("evidence/d.002")]
        first = self.run_it(parts).json
        path = self.path("out", "layers", first["descriptor"]["file"])
        before = os.stat(path)
        second = self.run_it(parts).json
        self.assertEqual(second["descriptor"]["file"], first["descriptor"]["file"])
        self.assertEqual((first["descriptor"]["created"], second["descriptor"]["created"], second["descriptor"]["already_present"]), (True, False, True))
        after = os.stat(path)
        self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))
        names = sorted(n for n in os.listdir(self.path("out", "layers")) if n.startswith("layer-"))
        self.assertEqual(names, [first["descriptor"]["file"]])
        # other inputs are another descriptor, beside the first
        third = self.run_it(parts[:1]).json
        self.assertNotEqual(third["descriptor"]["file"], first["descriptor"]["file"])
        self.assertEqual(len([n for n in os.listdir(self.path("out", "layers")) if n.startswith("layer-")]), 2)

    def test_a_descriptor_name_that_holds_other_bytes_is_not_replaced(self):
        parts = [self.raw("evidence/d.001")]
        first = self.run_it(parts).json
        path = self.path("out", "layers", first["descriptor"]["file"])
        os.chmod(path, 0o600)
        with open(path, "ab") as fh:
            fh.write(b" ")
        with open(path, "rb") as fh:
            changed = fh.read()
        res = self.run_it(parts)
        self.assertEqual(res.json["status"], "failed")
        self.assertIn("not replaced", res.json["status_basis"])
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), changed)

    def test_hash_sources_false_is_said_and_complete_does_not_depend_on_it(self):
        a = self.run_it([self.raw()], hash_sources=False).json
        self.assertIsNone(a["sources"][0]["sha256"])
        self.assertIn("hashing was not asked for", a["sources"][0]["not_hashed"])
        self.assertEqual(a["status"], CLEAN, a["status_basis"])

    @unittest.skipUnless(have("mmls") and have("fsstat") and have("img_stat"), "the Sleuth Kit is not installed")
    def test_a_4096_byte_sector_image_is_described_in_4096_byte_sectors_by_the_real_sleuth_kit(self):
        for sector, start in ((512, 2048), (4096, 256)):
            path = self.raw("evidence/s%d.dd" % sector, size=16 << 20, head=mbr(start, 3072 if sector == 4096 else 24576))
            if have("mke2fs") and sector == 4096:
                subprocess.run(["mke2fs", "-q", "-t", "ext4", "-b", "4096", "-E", "offset=%d" % (start * sector), path, "%dk" % (3072 * sector // 1024)], check=True, capture_output=True)
            a = run_tool("layer_describe", {"sources": [path], "sector_size": sector, "out_dir": self.path("out", "s%d" % sector)}, self.dir).json
            self.assertEqual(a["partition_table"], True, a)
            rows = [p for p in a["partitions"] if p["allocated"]]
            self.assertEqual([(p["offset_sectors"], p["offset_bytes"]) for p in rows], [(start, start * sector)], sector)
            d = json.loads(self.read(os.path.join(self.path("out", "s%d" % sector), a["descriptor"]["file"])))
            self.assertEqual(d["sector_size"], sector)
            self.assertEqual(d["partition_unit"], sector)
            self.assertIn("-b", d["programs"][-1]["argv"] if d["programs"] else [])
            if sector == 4096 and have("mke2fs"):
                self.assertEqual(rows[0]["filesystem"].get("fs_type"), "Ext4", a)
                self.assertEqual(a["status"], CLEAN, a["status_basis"])

    @unittest.skipUnless(have("ewfacquire") and have("ewfinfo") and have("mmls"), "ewf-tools or the Sleuth Kit is not installed")
    def test_a_real_e01_set_is_described_and_a_set_with_its_last_segment_missing_names_it(self):
        raw = self.raw("raw/disk.raw", size=4 << 20, head=mbr(2048, 6144))
        if have("mke2fs"):
            subprocess.run(["mke2fs", "-q", "-t", "ext4", "-E", "offset=%d" % (2048 * 512), raw, "%dk" % (6144 * 512 // 1024)], check=True, capture_output=True)
        os.makedirs(self.path("evidence"), exist_ok=True)
        made = subprocess.run(["ewfacquire", "-u", "-t", self.path("evidence", "real"), "-c", "none", "-S", "1MiB", "-m", "fixed", "-M", "logical", "-f", "encase6", "-d", "sha1",
                               "-C", "c", "-D", "d", "-e", "e", "-E", "ev", "-N", "n", raw], capture_output=True, timeout=120)
        self.assertEqual(made.returncode, 0, made.stderr)
        segments = sorted(os.path.join(self.path("evidence"), n) for n in os.listdir(self.path("evidence")))
        a = run_tool("layer_describe", {"sources": segments, "out_dir": self.path("out", "e01")}, self.dir).json
        self.assertEqual((a["container"]["layer"], a["media"]["bytes"], a["partition_table"]), ("ewf", 4 << 20, True), a["status_basis"])
        # complete where the file system is made and the host can adopt the orphans of its programs (CLEAN: Linux); partial elsewhere
        self.assertEqual(a["status"], CLEAN if have("mke2fs") else "partial", a["status_basis"])
        b = run_tool("layer_describe", {"sources": segments[:-1], "out_dir": self.path("out", "e01b")}, self.dir).json
        self.assertEqual(b["status"], "partial")
        self.assertEqual([d["kind"] for d in b["missing_dependencies"]], ["segment"])
        self.assertTrue(b["missing_dependencies"][0]["name"].endswith(".E%02d" % len(segments)))
        self.assertEqual(b["programs_total"], 0, "no program was run on an incomplete set")

    # ---- the declared and the undeclared
    def test_an_e01_set_with_a_missing_segment_lists_it_and_runs_nothing(self):
        paths = [self.write("evidence/d.E01", ewf_segment(1, False)), self.write("evidence/d.E03", ewf_segment(3, True))]
        log = self.path("calls.log")
        a = self.run_it(paths, path_dirs=[self.tools(log=log)]).json
        self.assertEqual(a["status"], "partial")
        self.assertEqual([(d["kind"], d["name"].rsplit("/", 1)[-1]) for d in a["missing_dependencies"]], [("segment", "d.E02")])
        self.assertNotEqual(a["status"], "complete")
        self.assertFalse(os.path.exists(log), "a program was run on an incomplete set")

    def test_ewf_segments_out_of_order_are_failed(self):
        paths = [self.write("evidence/d.E01", ewf_segment(1, False)), self.write("evidence/d.E03", ewf_segment(3, True)), self.write("evidence/d.E02", ewf_segment(2, False))]
        a = self.run_it(paths).json
        self.assertEqual(a["status"], "failed")
        self.assertIn("out of order", a["status_basis"])

    def test_a_vmdk_delta_whose_parent_is_not_declared_is_a_missing_dependency_and_no_program_looks_for_it(self):
        delta = self.write("evidence/delta.vmdk", vmdk_text(parent="base-parent.vmdk", extent="delta-flat.vmdk"))
        extent = self.write("evidence/delta-flat.vmdk", b"\0" * 2048)
        log = self.path("calls.log")
        a = self.run_it([delta, extent], path_dirs=[self.tools(log=log)]).json
        self.assertEqual(a["status"], "partial")
        self.assertEqual([(d["kind"], d["name"]) for d in a["missing_dependencies"]], [("parent", "base-parent.vmdk")])
        self.assertEqual(a["missing_dependencies"][0]["needed_by"], 0)
        self.assertFalse(os.path.exists(log), "qemu-img, mmls or fsstat was run on a disk whose parent is not declared")
        self.assertEqual(a["sources"][1]["role"], "extent")

    def test_a_declared_parent_satisfies_the_dependency_and_qemu_img_is_never_asked_for_the_chain(self):
        delta = self.write("evidence/delta.vmdk", vmdk_text(parent="base-parent.vmdk", extent="delta-flat.vmdk"))
        extent = self.write("evidence/delta-flat.vmdk", b"\0" * 2048)
        parent = self.write("evidence/base-parent.vmdk", vmdk_text(extent="base-flat.vmdk"))
        base_extent = self.write("evidence/base-flat.vmdk", b"\0" * 2048)
        log = self.path("calls.log")
        qemu = json.dumps({"format": "vmdk", "virtual-size": 1048576})
        a = self.run_it([delta, extent, parent, base_extent], path_dirs=[self.tools(log=log, qemu=qemu, img_type="vmdk", img_size=1048576)]).json
        self.assertEqual(a["missing_dependencies_count"], 0, a)
        calls = self.read(log)
        self.assertIn("qemu-img info --output=json", calls)
        self.assertNotIn("backing-chain", calls)
        self.assertEqual(a["media"], {"bytes": 1048576, "basis": "qemu-img info"})

    def test_a_qcow2_backing_file_and_a_vhd_parent_are_read_from_their_headers(self):
        qc = self.write("evidence/child.qcow2", qcow2(backing="/images/base.qcow2"))
        a = self.run_it([qc]).json
        self.assertEqual([(d["kind"], d["name"]) for d in a["missing_dependencies"]], [("backing file", "/images/base.qcow2")])
        self.assertEqual(a["container"]["layer"], "qcow")
        vh = self.write("evidence/child.vhd", vhd_differencing("C:\\vm\\parent.vhd"))
        b = self.run_it([vh]).json
        self.assertEqual(b["container"]["layer"], "vhd")
        self.assertEqual([(d["kind"], d["name"]) for d in b["missing_dependencies"]], [("parent", "C:\\vm\\parent.vhd")])
        parent = self.write("evidence/parent.vhd", vhd_footer(2) and (b"\0" * 1024 + vhd_footer(2)))
        c = self.run_it([vh, parent]).json
        self.assertEqual(c["missing_dependencies_count"], 0)
        self.assertEqual(c["sources"][1]["role"], "parent")

    def test_a_qemu_img_backing_name_that_is_not_declared_is_a_missing_dependency(self):
        top = self.write("evidence/x.vhd", vhd_footer(2) and (b"\0" * 1024 + vhd_footer(2)))
        qemu = json.dumps({"format": "vpc", "virtual-size": 1024, "backing-filename": "elsewhere.vhd"})
        a = self.run_it([top], path_dirs=[self.tools(qemu=qemu)]).json
        self.assertEqual([d["name"] for d in a["missing_dependencies"]], ["elsewhere.vhd"])
        self.assertNotEqual(a["status"], "complete")

    def test_a_mixed_set_and_a_logical_evidence_file_are_failed(self):
        a = self.run_it([self.write("evidence/a.E01", ewf_segment(1, True)), self.raw("evidence/b.dd")]).json
        self.assertEqual(a["status"], "failed")
        b = self.run_it([self.write("evidence/c.L01", b"LVF\x09\x0d\x0a\xff\x00" + b"\0" * 200)]).json
        self.assertEqual(b["status"], "failed")
        self.assertIn("unsupported", b["status_basis"])

    def test_a_program_that_is_missing_makes_it_partial(self):
        res = run_tool("layer_describe", {"sources": [self.raw()], "out_dir": self.path("out", "m")}, self.dir, only_path="")
        a = res.json
        self.assertEqual(a["status"], "partial")
        self.assertIn("not on PATH", a["status_basis"])
        self.assertIsNotNone(a["descriptor"])

    # ---- hostile sources
    def test_a_symlink_a_fifo_a_directory_and_an_unreadable_file_are_refused_without_waiting(self):
        good = self.raw()
        link = self.path("evidence", "link.dd")
        os.symlink(good, link)
        loop = self.path("evidence", "loop.dd")
        os.symlink(loop, loop)
        fifo = self.path("evidence", "fifo.dd")
        os.mkfifo(fifo)
        directory = self.path("evidence", "dir.dd")
        os.mkdir(directory)
        locked = self.raw("evidence/locked.dd")
        os.chmod(locked, 0)
        try:
            for bad in (link, loop, fifo, directory) + ((locked,) if os.geteuid() != 0 else ()):
                started = time.monotonic()
                res = self.run_it([bad], out_dir=self.path("out", os.path.basename(bad)))
                self.assertLess(time.monotonic() - started, 20, bad)
                a = res.json
                self.assertEqual(a["status"], "failed", bad)
                self.assertIsNone(a["descriptor"], bad)
                self.assertEqual(a["programs_total"], 0, bad)
        finally:
            os.chmod(locked, 0o600)

    def test_a_name_shaped_like_a_token_is_not_printed_and_the_descriptor_is_private(self):
        token = "AKIAIOSFODNN7EXAMPLEzzqq0987654321"
        path = self.raw("evidence/%s.dd" % token)
        res = self.run_it([path])
        self.assertNotIn(token, res.stdout)
        self.assertNotIn(token, res.stderr)
        descriptor = self.path("out", "layers", res.json["descriptor"]["file"])
        self.assertIn(token, self.read(descriptor), "the descriptor holds the declared path, for a consumer to open")
        self.assertEqual(oct(os.stat(descriptor).st_mode & 0o777), "0o600")

    def test_the_arguments_are_checked(self):
        good = self.raw()
        for args in ({}, {"sources": []}, {"sources": [3]}, {"sources": [good, good]}, {"sources": [good], "sector_size": 100}, {"sources": [good], "sector_size": 513},
                     {"sources": [good], "hash_sources": "yes"}, {"sources": [good], "other": 1}, {"sources": [good], "max_seconds": 0}):
            res = run_tool("layer_describe", args, self.dir)
            self.assertEqual(res.code, 1, args)
            self.assertEqual(res.json["status"], "failed", args)

    # ---- stops and writes
    def test_a_stop_signal_ends_the_program_leaves_no_temporary_and_gives_one_partial_document(self):
        pids = self.path("pids")
        d = self.tools()
        stand_in(d, "mmls", 'echo $$ > %s\nexec sleep 60\n' % pids)
        env = dict(os.environ, PATH=d + os.pathsep + os.environ["PATH"])
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            env.pop(k, None)
        src = self.raw()
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            out = self.path("out", "stop%d" % signum)
            spec = self.write("spec%d.json" % signum, json.dumps({"sources": [src], "out_dir": out}))
            stdin = open(spec, "rb")
            self.addCleanup(stdin.close)
            proc = subprocess.Popen([sys.executable, tool_path("layer_describe")], stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.dir, env=env, start_new_session=True)
            try:
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline and not (os.path.exists(pids) and self.read("pids").strip()):
                    time.sleep(0.05)
                pid = int(self.read("pids").strip())
                os.kill(proc.pid, signum)
                stdout, _ = proc.communicate(timeout=20)
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
            self.assertEqual(proc.returncode, 128 + signum)
            doc = json.loads(stdout)
            self.assertEqual((doc["status"], doc["interrupted"], doc["signal"]), ("partial", True, signum))
            time.sleep(0.3)
            self.assertFalse(os.path.exists("/proc/%d" % pid) and open("/proc/%d/stat" % pid).read().split()[2] != "Z", "mmls was left running")
            self.assertEqual([n for n in os.listdir(out) if n.startswith(".") or n.startswith("layer-")], [], "a temporary or a descriptor was left")
            os.unlink(pids)

    def test_a_program_that_outlives_its_budget_is_ended(self):
        d = self.tools()
        stand_in(d, "mmls", "exec sleep 600\n")
        started = time.monotonic()
        res = run_tool("layer_describe", {"sources": [self.raw()], "out_dir": self.path("out", "slow"), "max_seconds": 8}, self.dir, path_dirs=[d], timeout=60)
        self.assertLess(time.monotonic() - started, 30)
        self.assertEqual(res.json["status"], "partial")

    def test_a_file_size_limit_never_leaves_a_half_descriptor_or_a_wrong_claim(self):
        env = dict(os.environ, PATH=self.tools() + os.pathsep + os.environ["PATH"])
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            env.pop(k, None)
        out = self.path("out", "limited")
        src = self.raw()
        proc = subprocess.run([sys.executable, tool_path("layer_describe")], input=json.dumps({"sources": [src], "out_dir": out}).encode(), capture_output=True, cwd=self.dir, env=env,
                              timeout=60, preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (1000, 1000)))
        a = json.loads(proc.stdout)
        self.assertNotEqual(a["status"], "complete", a["status_basis"])
        self.assertEqual(a["status"], "failed")
        self.assertEqual([n for n in os.listdir(out) if n.startswith(".") or n.startswith("layer-")], [], "a temporary or a half descriptor was left")


if __name__ == "__main__":
    unittest.main()
