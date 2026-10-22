"""disk-volumes: what a partition table can say about itself, and cannot make the recipe do.

mmls prints a GPT partition name raw. A name that holds a line break followed by a forged row used to become a second row of the table, and
its third column became a directory name under the output directory: `../../../x` left it. These tests run the recipe as the harness
does (`run.sh run --target T --out DIR`) with stand-in Sleuth Kit programs, and once with the real ones over a hand-built GPT image.
"""
import json
import os
import struct
import subprocess
import unittest
import uuid
import zlib

from support import Case, have, recipe_path, stand_in

FORGED = "9:  0 ../../../g0001/p2048 1 1 z"

MMLS_FORGED = """GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000       0000002048   0000002559   0000000512   x
%s
003:  001       0000002560   0000003071   0000000512   second
"""


def gpt_image(first_name):
    """A GPT disk of 4096 sectors whose first partition carries `first_name` (UTF-16LE, up to 36 characters), laid out as the UEFI specification does."""
    sec, total = 512, 4096
    img = bytearray(total * sec)
    img[446 + 4] = 0xEE
    struct.pack_into("<II", img, 446 + 8, 1, total - 1)
    img[510:512] = b"\x55\xaa"

    def entry(first, last, name):
        e = bytearray(128)
        e[0:16] = uuid.UUID("0FC63DAF-8483-4772-8E79-3D69D8477DE4").bytes_le
        e[16:32] = uuid.uuid4().bytes_le
        struct.pack_into("<QQQ", e, 32, first, last, 0)
        e[56:56 + 72] = name.encode("utf-16le")[:72].ljust(72, b"\0")
        return bytes(e)

    entries = (entry(2048, 2559, first_name) + entry(2560, 3071, "second")).ljust(128 * 128, b"\0")
    header = bytearray(92)
    header[0:8] = b"EFI PART"
    struct.pack_into("<IIII", header, 8, 0x10000, 92, 0, 0)
    struct.pack_into("<QQQQ", header, 24, 1, total - 1, 34, total - 34)
    header[56:72] = uuid.uuid4().bytes_le
    struct.pack_into("<QIII", header, 72, 2, 128, 128, zlib.crc32(entries) & 0xFFFFFFFF)
    struct.pack_into("<I", header, 16, zlib.crc32(bytes(header)) & 0xFFFFFFFF)
    img[sec:sec + 92] = header
    img[2 * sec:2 * sec + len(entries)] = entries
    return bytes(img)


class DiskVolumes(Case):
    def run_recipe(self, image, out, bin_dir=None):
        env = dict(os.environ)
        if bin_dir:
            env["PATH"] = bin_dir + os.pathsep + env["PATH"]
        target = json.dumps({"paths": [image], "name": "disk.img"})
        return subprocess.run(["bash", recipe_path("disk-volumes", "run.sh"), "run", "--target", target, "--out", out],
                              cwd=self.dir, env=env, capture_output=True, text=True, timeout=120)

    def stubs(self, mmls_text, fsstat_ok=False):
        d = self.path("bin")
        os.makedirs(d, exist_ok=True)
        self.write("mmls.txt", mmls_text)
        stand_in(d, "mmls", 'cat "%s"\n' % self.path("mmls.txt"))
        # An unreadable partition is the case that writes: run_step truncates its output file and removes it when it stays empty.
        stand_in(d, "fsstat", "echo 'Cannot determine file system type' >&2\nexit 1\n" if not fsstat_ok else "echo 'File System Type: Ext4'\n")
        stand_in(d, "fls", "echo 'Cannot determine file system type' >&2\nexit 1\n")
        return d

    def test_a_forged_row_in_a_partition_name_does_not_leave_the_output_directory_or_delete_another_files(self):
        bin_dir = self.stubs(MMLS_FORGED % FORGED)
        image = self.write("disk.img", b"\0" * 65536)
        victim = self.path("box/catalog/gen/g0001/p2048")
        os.makedirs(victim)
        for name in ("fsstat.txt", "bodyfile.txt", "filelist.txt"):
            self.write("box/catalog/gen/g0001/p2048/" + name, "another generation's listing\n")
        r = self.run_recipe(image, self.path("box/catalog/gen/g0002"), bin_dir)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for name in ("fsstat.txt", "bodyfile.txt", "filelist.txt"):
            self.assertEqual(self.read("box/catalog/gen/g0001/p2048/" + name), "another generation's listing\n", name)
        self.assertEqual(sorted(os.listdir(victim)), ["bodyfile.txt", "filelist.txt", "fsstat.txt"], "nothing was added beside them")
        self.assertEqual(sorted(os.listdir(self.path("box/catalog/gen"))), ["g0001", "g0002"], "no directory was made outside the output directory")
        out = self.path("box/catalog/gen/g0002")
        self.assertEqual(sorted(d for d in os.listdir(out) if d[1:].isdigit()), ["p2048", "p2560"], "the two real entries, and only them")
        cov = json.loads(self.read(out + "/coverage.json"))
        self.assertEqual(cov["status"], "partial")
        self.assertEqual([e["start_sector"] for e in cov["inventory"]], [2048, 2560])
        self.assertTrue([e for e in cov["errors"] if "is not a row of the table" in e and "partitions.txt" in e], cov["errors"])

    def test_a_forged_row_that_looks_like_a_row_is_out_of_sequence_and_is_not_a_partition(self):
        forged = "007:  000       0000009999   0000010000   0000000002   forged"
        bin_dir = self.stubs(MMLS_FORGED % forged)
        r = self.run_recipe(self.write("disk.img", b"\0" * 65536), self.path("out"), bin_dir)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cov = json.loads(self.read("out/coverage.json"))
        self.assertNotIn(9999, [e["start_sector"] for e in cov["inventory"]])
        self.assertFalse(os.path.exists(self.path("out/p9999")))
        self.assertTrue([e for e in cov["errors"] if "is row 7 where row 3 was due" in e], cov["errors"])

    def test_a_description_has_no_control_character_in_the_inventory_or_the_index(self):
        table = MMLS_FORGED % "003:  001       0000002560   0000003071   0000000512   tab\there\x01"
        bin_dir = self.stubs(table.replace("003:  001       0000002560   0000003071   0000000512   second\n", ""))
        r = self.run_recipe(self.write("disk.img", b"\0" * 65536), self.path("out"), bin_dir)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cov = json.loads(self.read("out/coverage.json"))
        self.assertIn("tab?here?", [e["description"] for e in cov["inventory"]])
        self.assertEqual(len(self.read("out/index.tsv").splitlines()[0].split("\t")), 2, "a tab in a name does not add a column to the index")

    @unittest.skipUnless(have("mmls") and have("fsstat"), "the Sleuth Kit is not installed on this host")
    def test_with_the_real_mmls_a_gpt_name_that_holds_a_forged_row_does_the_same_nothing(self):
        image = self.write("gpt.img", gpt_image("x\n" + FORGED))
        victim = self.path("box/catalog/gen/g0001/p2048")
        os.makedirs(victim)
        self.write("box/catalog/gen/g0001/p2048/fsstat.txt", "keep\n")
        r = self.run_recipe(image, self.path("box/catalog/gen/g0002"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.read("box/catalog/gen/g0001/p2048/fsstat.txt"), "keep\n")
        self.assertEqual(sorted(os.listdir(victim)), ["fsstat.txt"])
        self.assertEqual(sorted(os.listdir(self.path("box/catalog/gen"))), ["g0001", "g0002"])
        cov = json.loads(self.read("box/catalog/gen/g0002/coverage.json"))
        self.assertEqual(cov["status"], "partial")

    def test_a_clean_table_is_read_as_before(self):
        clean = MMLS_FORGED.replace("%s\n", "")
        bin_dir = self.stubs(clean, fsstat_ok=True)
        stand_in(bin_dir, "mactime", "echo 'Date,Size,Type,Mode,UID,GID,Meta,File Name'\n")
        stand_in(bin_dir, "fls", "case \"$1\" in -m) echo '0|/a|12|r/rrw-r--r--|0|0|9|0|0|0|0';; *) echo 'r/r 12:\ta';; esac\n")
        r = self.run_recipe(self.write("disk.img", b"\0" * 65536), self.path("out"), bin_dir)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(json.loads(r.stdout)["candidate_volumes"], 2)
        self.assertEqual(json.loads(self.read("out/coverage.json"))["errors"], [])


if __name__ == "__main__":
    unittest.main()
