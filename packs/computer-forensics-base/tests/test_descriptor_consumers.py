"""image_layout, icat_extract and chunk_needles take `descriptor:` in place of image and sector_size, and give the answer the same image gives by path.

The image is built here (an MBR, one ext4 volume made with mke2fs -d holding a known file), laid out as one raw file, as three raw segments and as an
E01 set; layer_describe writes the descriptors; the real Sleuth Kit and libewf are the readers. Forged descriptors are refused before anything runs.
"""
import hashlib
import json
import os
import struct
import subprocess
import unittest

from support import Case, have, recipe_path, run_tool

CONTENT = b"alpha NEEDLE-ONE-xyz beta NEEDLE-ONE-xyz\n"
NEEDED = ("mke2fs", "sfdisk", "mmls", "fsstat", "icat", "fls", "img_stat")


@unittest.skipUnless(all(have(p) for p in NEEDED), "the Sleuth Kit, sfdisk and mke2fs are needed")
class DescriptorConsumers(Case):
    def setUp(self):
        super().setUp()
        src = self.path("src")
        os.makedirs(src)
        with open(os.path.join(src, "hello.txt"), "wb") as fh:
            fh.write(CONTENT)
        self.raw = self.path("evidence", "disk.raw")
        os.makedirs(self.path("evidence"))
        with open(self.raw, "wb") as fh:
            fh.truncate(16 << 20)
        subprocess.run(["sfdisk", self.raw], input=b"start=2048, size=24576, type=83\n", check=True, capture_output=True)
        subprocess.run(["mke2fs", "-q", "-t", "ext4", "-E", "offset=%d" % (2048 * 512), "-d", src, self.raw, "12M"], check=True, capture_output=True)
        listing = subprocess.run(["fls", "-o", "2048", self.raw], capture_output=True, text=True, check=True).stdout
        self.inode = [ln.split(":")[0].split()[-1] for ln in listing.splitlines() if ln.endswith("hello.txt")][0]
        # three raw segments of the same bytes
        with open(self.raw, "rb") as fh:
            data = fh.read()
        self.parts = []
        for n in range(3):
            self.parts.append(self.write("evidence/split.00%d" % (n + 1), data[n * (6 << 20):(n + 1) * (6 << 20)]))
        self.e01 = None
        if have("ewfacquire") and have("ewfinfo"):
            made = subprocess.run(["ewfacquire", "-u", "-t", self.path("evidence", "set"), "-c", "none", "-S", "4MiB", "-m", "fixed", "-M", "logical", "-f", "encase6", "-d", "sha1",
                                   "-C", "c", "-D", "d", "-e", "e", "-E", "ev", "-N", "n", self.raw], capture_output=True, timeout=120)
            if made.returncode == 0:
                self.e01 = sorted(self.path("evidence", n) for n in os.listdir(self.path("evidence")) if n.startswith("set.E"))

    def describe(self, sources, **extra):
        a = run_tool("layer_describe", dict(extra, sources=sources, out_dir=self.path("out", "layers")), self.dir).json
        self.assertEqual(a["status"], "complete", a["status_basis"])
        return os.path.join(self.path("out", "layers"), a["descriptor"]["file"]), a

    def layouts(self):
        out = {"raw": [self.raw], "split": self.parts}
        if self.e01:
            out["e01"] = self.e01
        return out

    def extract(self, name, **args):
        return run_tool("icat_extract", dict(args, inode=self.inode, output="work/out/%s.bin" % name), self.dir)

    # ---- the same answer as the path gives
    def test_icat_extract_by_descriptor_writes_the_bytes_the_path_writes_for_every_layout(self):
        direct = self.extract("direct", image=self.raw, offset=2048).json
        self.assertEqual(direct["status"], "complete")
        self.assertEqual(direct["sha256"], hashlib.sha256(CONTENT).hexdigest())
        for layout, sources in self.layouts().items():
            descriptor, _ = self.describe(sources)
            res = self.extract("by-" + layout, descriptor=descriptor)
            a = res.json
            self.assertEqual((res.code, a["status"], a["size"], a["sha256"]), (0, "complete", direct["size"], direct["sha256"]), (layout, a))
            self.assertEqual(a["offset"], 2048)
            self.assertEqual(a["descriptor"]["layer"], {"raw": "raw", "split": "split_raw", "e01": "ewf"}[layout])
            self.assertEqual(a["images"], len(sources))
            self.assertEqual(self.read(a["path"] if os.path.isabs(a["path"]) else a["path"], "rb"), CONTENT)

    def test_chunk_needles_by_descriptor_counts_what_the_path_counts(self):
        direct = run_tool("chunk_needles", {"inode": self.inode, "image": self.raw, "offset": 2048, "needles": ["NEEDLE-ONE-xyz"]}, self.dir).json
        self.assertEqual(direct["status"], "complete", direct)
        for layout, sources in self.layouts().items():
            descriptor, _ = self.describe(sources)
            a = run_tool("chunk_needles", {"inode": self.inode, "descriptor": descriptor, "needles": ["NEEDLE-ONE-xyz"]}, self.dir).json
            self.assertEqual(a["status"], "complete", (layout, a))
            self.assertEqual([h["ascii"] for h in a["hits"].values()] if isinstance(a["hits"], dict) else a["hits"], [h["ascii"] for h in direct["hits"].values()] if isinstance(direct["hits"], dict) else direct["hits"], layout)
            self.assertEqual(a["scanned_bytes"], direct["scanned_bytes"], layout)
            self.assertEqual(a["source"]["descriptor"]["sha256"], os.path.basename(descriptor)[6:-5])

    def test_image_layout_by_descriptor_finds_the_same_volume_the_path_finds(self):
        def volume(answer):
            return [(p["offset_sectors"], p["filesystem"].get("fs_type")) for p in answer["partitions"] if "filesystem" in p and p["filesystem"].get("readable")]
        direct = run_tool("image_layout", {"image": self.raw}, self.dir).json
        self.assertEqual(volume(direct), [(2048, "Ext4")])
        for layout, sources in self.layouts().items():
            descriptor, _ = self.describe(sources)
            a = run_tool("image_layout", {"descriptor": descriptor}, self.dir).json
            self.assertEqual(volume(a), [(2048, "Ext4")], layout)
            self.assertEqual((a["partition_table"], a["sector_size"], a["volumes_readable"]), (direct["partition_table"], direct["sector_size"], direct["volumes_readable"]), layout)
            self.assertEqual(a["descriptor"]["sha256"], os.path.basename(descriptor)[6:-5])
            self.assertEqual(a["images"], len(sources))

    def test_a_4096_byte_descriptor_passes_its_sector_size_as_b(self):
        path = self.path("evidence", "s4k.dd")
        with open(path, "wb") as fh:
            fh.truncate(16 << 20)
        sector = bytearray(512)
        sector[446 + 4] = 0x83
        struct.pack_into("<II", sector, 446 + 8, 256, 3072)
        sector[510:512] = b"\x55\xaa"
        with open(path, "r+b") as fh:
            fh.write(bytes(sector))
        subprocess.run(["mke2fs", "-q", "-t", "ext4", "-b", "4096", "-E", "offset=%d" % (256 * 4096), "-d", self.path("src"), path, "%dk" % (3072 * 4)], check=True, capture_output=True)
        descriptor, a = self.describe([path], sector_size=4096)
        self.assertEqual(a["partition_table"], True)
        lay = run_tool("image_layout", {"descriptor": descriptor}, self.dir).json
        self.assertEqual((lay["sector_size"], lay["sector_size_source"]), (4096, "given by the caller (-b)"))
        direct = run_tool("image_layout", {"image": path, "sector_size": 4096}, self.dir).json
        self.assertEqual([p.get("offset_sectors") for p in lay["partitions"]], [p.get("offset_sectors") for p in direct["partitions"]])
        listing = subprocess.run(["fls", "-b", "4096", "-o", "256", path], capture_output=True, text=True).stdout
        inode = [ln.split(":")[0].split()[-1] for ln in listing.splitlines() if ln.endswith("hello.txt")][0]
        res = run_tool("icat_extract", {"descriptor": descriptor, "inode": inode, "output": "work/out/k4.bin"}, self.dir).json
        self.assertEqual((res["status"], res["sector_size"], res["sha256"]), ("complete", 4096, hashlib.sha256(CONTENT).hexdigest()), res)

    # ---- forged descriptors and what is given beside one
    def forge(self, descriptor, edit):
        with open(descriptor, "rb") as fh:
            doc = json.loads(fh.read())
        edit(doc)
        body = (json.dumps(doc, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
        path = self.path("out", "forged", "layer-%s.json" % hashlib.sha256(body).hexdigest())
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(body)
        return path

    def refused(self, tool, args, words):
        extra = {"inode": self.inode, "output": "work/out/never.bin"} if tool == "icat_extract" else ({"inode": self.inode, "needles": ["x"]} if tool == "chunk_needles" else {})
        res = run_tool(tool, dict(extra, **args), self.dir)
        self.assertEqual(res.code, 1, (tool, args, res.stdout[:300]))
        self.assertEqual(res.json["status"], "failed", (tool, args))
        self.assertIn(words, res.json["status_basis"], (tool, args))
        self.assertFalse(os.path.exists(self.path("work", "out", "never.bin")))

    def test_a_descriptor_whose_bytes_do_not_hash_to_its_name_is_refused_by_all_three(self):
        descriptor, _ = self.describe(self.parts)
        with open(descriptor, "r+b") as fh:
            fh.seek(30)
            byte = fh.read(1)
            fh.seek(30)
            fh.write(bytes([byte[0] ^ 1]))
        for tool in ("image_layout", "icat_extract", "chunk_needles"):
            self.refused(tool, {"descriptor": descriptor}, "do not hash to the name")

    def test_a_pin_that_is_not_the_descriptors_sha256_is_refused(self):
        descriptor, _ = self.describe([self.raw])
        for tool in ("image_layout", "icat_extract", "chunk_needles"):
            self.refused(tool, {"descriptor": descriptor, "descriptor_sha256": "0" * 64}, "pins")

    def test_an_offset_past_the_end_and_an_offset_that_is_not_a_volume_are_refused(self):
        descriptor, _ = self.describe([self.raw])
        past = self.forge(descriptor, lambda d: [x for x in d["partitions"] if "filesystem" in x][0].update(offset_sectors=99999999, offset_bytes=99999999 * 512))
        elsewhere = self.forge(descriptor, lambda d: [x for x in d["partitions"] if "filesystem" in x][0].update(offset_sectors=4096, offset_bytes=4096 * 512))
        for tool in ("image_layout", "icat_extract", "chunk_needles"):
            self.refused(tool, {"descriptor": past}, "past the end")
        self.assertEqual(run_tool("icat_extract", {"descriptor": elsewhere, "inode": self.inode, "output": "work/out/e.bin", "offset": 2048}, self.dir).json["status"], "failed")
        self.refused("icat_extract", {"descriptor": descriptor, "offset": 4096}, "not a volume of the descriptor")
        self.refused("chunk_needles", {"descriptor": descriptor, "offset": 4096}, "not a volume of the descriptor")

    def test_a_declared_source_that_changed_after_hashing_is_found_by_size_and_by_verify_sources(self):
        descriptor, _ = self.describe(self.parts)
        with open(self.parts[1], "r+b") as fh:                     # the same size, other bytes
            fh.seek(100)
            fh.write(b"swapped!")
        ok = self.extract("swapped-size-only", descriptor=descriptor)
        self.assertEqual(ok.json["descriptor"]["sources_checked"], "sizes", "a swap of the same size is not found by the size check, and the answer says what was checked")
        for tool in ("icat_extract", "chunk_needles"):
            self.refused(tool, {"descriptor": descriptor, "verify_sources": True}, "no longer hashes")
        with open(self.parts[2], "ab") as fh:                      # another size
            fh.write(b"x")
        for tool in ("image_layout", "icat_extract", "chunk_needles"):
            self.refused(tool, {"descriptor": descriptor}, "it changed after the descriptor was made")

    def test_a_descriptor_that_lists_a_missing_dependency_is_refused(self):
        descriptor, _ = self.describe([self.raw])
        listed = self.forge(descriptor, lambda d: d.update(missing_dependencies=[{"kind": "segment", "name": "x.E02", "needed_by": 0, "declared": False}]))
        for tool in ("image_layout", "icat_extract", "chunk_needles"):
            self.refused(tool, {"descriptor": listed}, "missing_dependencies")

    def test_image_and_descriptor_together_and_a_descriptor_that_is_a_fifo_are_refused(self):
        descriptor, _ = self.describe([self.raw])
        for tool in ("image_layout", "icat_extract", "chunk_needles"):
            self.refused(tool, {"descriptor": descriptor, "image": self.raw}, "replaces image and sector_size")
            self.refused(tool, {"descriptor": descriptor, "sector_size": 512}, "replaces image and sector_size")
        fifo = self.path("out", "layer-" + "0" * 64 + ".json")
        os.makedirs(os.path.dirname(fifo), exist_ok=True)
        os.mkfifo(fifo)
        for tool in ("image_layout", "icat_extract", "chunk_needles"):
            self.refused(tool, {"descriptor": fifo}, "descriptor")


@unittest.skipUnless(all(have(p) for p in NEEDED + ("perl", "mactime")), "the recipe needs the Sleuth Kit, perl and mactime")
class DiskVolumesDescriptor(DescriptorConsumers):
    """The disk-volumes recipe reads a descriptor by reference and covers the volumes the path covers."""

    def recipe(self, target, name):
        out = self.path("out", name)
        proc = subprocess.run(["bash", recipe_path("disk-volumes", "run.sh"), "run", "--target", json.dumps(target), "--out", out], capture_output=True, text=True, timeout=300, cwd=self.dir)
        return proc, out

    def test_the_recipe_covers_the_same_volumes_by_descriptor_as_by_path(self):
        proc, direct = self.recipe({"paths": [self.raw]}, "direct")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        want = self.read(os.path.join(direct, "p2048", "filelist.txt"))
        for layout, sources in self.layouts().items():
            descriptor, _ = self.describe(sources)
            proc, out = self.recipe({"descriptor": descriptor, "name": "disk"}, "by-" + layout)
            self.assertEqual(proc.returncode, 0, (layout, proc.stdout[:400], proc.stderr[:400]))
            self.assertEqual(self.read(os.path.join(out, "p2048", "filelist.txt")), want, layout)
            self.assertEqual(self.read(os.path.join(out, "p2048", "fsstat.txt")), self.read(os.path.join(direct, "p2048", "fsstat.txt")), layout)
            self.assertEqual(self.read(os.path.join(out, "partitions.txt")), self.read(os.path.join(direct, "partitions.txt")), layout)
            coverage = json.loads(self.read(os.path.join(out, "coverage.json")))
            kept = json.loads(self.read(os.path.join(out, "descriptor.json")))
            self.assertEqual(kept["sha256"], os.path.basename(descriptor)[6:-5])
            self.assertIn("descriptor.json", self.read(os.path.join(out, "index.tsv")))
            self.assertEqual(coverage["status"], "complete", coverage)

    def test_the_recipe_refuses_a_forged_descriptor_before_it_runs_anything(self):
        descriptor, _ = self.describe([self.raw])
        with open(descriptor, "r+b") as fh:
            fh.seek(30)
            byte = fh.read(1)
            fh.seek(30)
            fh.write(bytes([byte[0] ^ 1]))
        proc, out = self.recipe({"descriptor": descriptor}, "forged")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("do not hash to the name", proc.stdout)
        self.assertFalse(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
