"""image_layout: one sector size for the programs and the arithmetic, VHD, and a failure that is not "no partition table".

mmls and fsstat are stand-ins that print the Sleuth Kit's documented output
format and record their arguments, so the tests hold on any host; a last test
runs the real mmls over a hand-built MBR image when the host has it.
"""
import os
import struct
import unittest

from support import Case, have, run_tool, stand_in

# What mmls prints (TSK's documented layout) for a table in 4096-byte sectors.
MMLS_4K = """GUID Partition Table (EFI)
Offset Sector: 0
Units are in 4096-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000000005   0000000006   Unallocated
002:  Meta      0000000001   0000000001   0000000001   GPT Header
003:  Meta      0000000002   0000000005   0000000004   Partition Table
004:  000       0000000006   0000250000   0000249995   Basic data partition
"""
FSSTAT_NTFS = """FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Volume Serial Number: 0123456789ABCDEF
Sector Size: 4096
Cluster Size: 4096
Total Cluster Range: 0 - 249994
"""


def vhd_footer():
    """A VHD footer as the Microsoft VHD specification lays it out: the cookie
    "conectix" first, then features, version, data offset and so on."""
    footer = bytearray(512)
    footer[0:8] = b"conectix"
    struct.pack_into(">I", footer, 8, 2)            # features: reserved bit set
    struct.pack_into(">I", footer, 12, 0x00010000)  # file format version 1.0
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)   # data offset: none for a fixed disk
    footer[0x24:0x28] = b"win "
    struct.pack_into(">I", footer, 0x3C, 2)         # disk type: fixed
    return bytes(footer)


class ImageLayout(Case):
    def stubs(self, mmls="", fsstat="", img_stat="echo 'IMAGE FILE INFORMATION'\n"):
        d = self.path("bin")
        os.makedirs(d, exist_ok=True)
        log = self.path("calls.log")
        stand_in(d, "mmls", 'echo "mmls $*" >> "%s"\n%s' % (log, mmls or "exit 1\n"))
        stand_in(d, "fsstat", 'echo "fsstat $*" >> "%s"\n%s' % (log, fsstat or "echo 'Cannot determine file system type' >&2; exit 1\n"))
        stand_in(d, "img_stat", 'echo "img_stat $*" >> "%s"\n%s' % (log, img_stat))
        return d, log

    def calls(self, log):
        return self.read(log).splitlines() if os.path.exists(log) else []

    def image(self, name="disk.img", data=b"\0" * 4096):
        return self.write(name, data)

    def test_a_forced_sector_size_is_passed_to_mmls_and_fsstat(self):
        bin_dir, log = self.stubs("cat <<'EOF'\n%sEOF\n" % MMLS_4K, "cat <<'EOF'\n%sEOF\n" % FSSTAT_NTFS)
        image = self.image()
        r = run_tool("image_layout", {"image": image, "sector_size": 4096}, self.dir, [bin_dir])
        self.assertEqual(r.code, 0, r.stdout)
        calls = self.calls(log)
        self.assertIn("mmls -b 4096 %s" % image, calls)
        self.assertIn("fsstat -b 4096 -o 6 %s" % image, calls)
        part = [p for p in r.json["partitions"] if p.get("allocated")][0]
        self.assertEqual(part["offset_bytes"], 6 * 4096)
        self.assertEqual(part["filesystem"]["readable"], True)
        self.assertIn("-b 4096", r.json["use"][0]["example"])
        self.assertEqual(r.json["sector_size"], 4096)

    def test_the_unit_mmls_printed_is_the_unit_fsstat_gets(self):
        # No sector_size given: mmls says "Units are in 4096-byte sectors", and the offsets it
        # printed are in those sectors, so fsstat must be told the same unit.
        bin_dir, log = self.stubs("cat <<'EOF'\n%sEOF\n" % MMLS_4K, "cat <<'EOF'\n%sEOF\n" % FSSTAT_NTFS)
        image = self.image()
        r = run_tool("image_layout", {"image": image}, self.dir, [bin_dir])
        self.assertIn("fsstat -b 4096 -o 6 %s" % image, self.calls(log))
        self.assertEqual(r.json["sector_size_source"], "the units line of mmls")

    def test_a_sector_size_the_sleuth_kit_cannot_take_is_refused(self):
        bin_dir, log = self.stubs()
        for bad in (1000, 0, 100, True, "4096"):
            r = run_tool("image_layout", {"image": self.image(), "sector_size": bad}, self.dir, [bin_dir])
            self.assertEqual(r.code, 1, bad)
        self.assertEqual(self.calls(log), [])

    def test_both_vhd_forms_are_recognised(self):
        bin_dir, _ = self.stubs()
        dynamic = self.write("dyn.vhd", vhd_footer() + b"\0" * 4096)      # a dynamic disk starts with a copy of the footer
        fixed = self.write("fixed.vhd", b"\0" * 8192 + vhd_footer())      # a fixed disk's footer is its last 512 bytes
        for path, where in ((dynamic, "offset 0"), (fixed, "last 512")):
            r = run_tool("image_layout", {"image": path}, self.dir, [bin_dir])
            self.assertEqual(r.json["container"], "vhd", path)
            self.assertIn(where, r.json["container_basis"])

    def test_other_containers_by_their_signatures(self):
        bin_dir, _ = self.stubs()
        for name, head, want in (("a.E01", b"EVF\x09\x0d\x0a\xff\x00", "ewf"), ("a.qcow2", b"QFI\xfb\x00\x00\x00\x03", "qcow"),
                                 ("a.vhdx", b"vhdxfile", "vhdx"), ("a.vmdk", b"KDMV\x01\x00\x00\x00", "vmdk"),
                                 ("plain.dd", b"\0" * 64, "raw")):
            r = run_tool("image_layout", {"image": self.write(name, head + b"\0" * 1024)}, self.dir, [bin_dir])
            self.assertEqual(r.json["container"], want, name)

    def test_an_mmls_that_failed_is_not_no_partition_table(self):
        image = self.image()
        # It ran and complained of the image: nothing is known about a table.
        bin_dir, _ = self.stubs("echo 'Error stat(ing) image file (raw_open: image \"x\" - Permission denied)' >&2; exit 1\n")
        r = run_tool("image_layout", {"image": image}, self.dir, [bin_dir])
        self.assertEqual(r.json["partition_table"], "unknown")
        self.assertIn("Permission denied", r.json["mmls_error"])
        # It is not on PATH at all.
        empty = self.path("empty")
        os.makedirs(empty)
        r = run_tool("image_layout", {"image": image}, self.dir, only_path=empty)
        self.assertEqual(r.json["partition_table"], "unknown")
        self.assertIn("not on PATH", r.json["mmls_error"])
        # It timed out is the same class; a failure to find a table (exit 1, nothing said) is the other answer.
        bin_dir, _ = self.stubs("exit 1\n")
        r = run_tool("image_layout", {"image": image}, self.dir, [bin_dir])
        self.assertIs(r.json["partition_table"], False)
        self.assertIn("recognises", r.json["partition_table_basis"])
        self.assertTrue(any("filesystem/encrypted" in n for n in r.json["notes"]))

    def test_a_split_raw_first_segment_is_said_to_be_one_segment(self):
        bin_dir, _ = self.stubs()
        first = self.write("disk.001", b"\0" * 1024)
        self.write("disk.002", b"\0" * 1024)
        r = run_tool("image_layout", {"image": first}, self.dir, [bin_dir])
        self.assertTrue(any("one path" in n and "disk.002" in n for n in r.json["notes"]), r.json["notes"])

    def test_the_programs_output_is_kept_whole(self):
        bin_dir, _ = self.stubs("cat <<'EOF'\n%sEOF\n" % MMLS_4K, "cat <<'EOF'\n%sEOF\n" % FSSTAT_NTFS)
        r = run_tool("image_layout", {"image": self.image()}, self.dir, [bin_dir])
        kept = self.path(r.json["raw_outputs"]["mmls"])
        self.assertIn("Basic data partition", self.read(kept))

    def test_a_silent_mmls_failure_is_no_table_only_when_img_stat_opens_the_image(self):
        image = self.image()
        bin_dir, log = self.stubs("exit 1\n")
        r = run_tool("image_layout", {"image": image}, self.dir, [bin_dir])
        self.assertIs(r.json["partition_table"], False)
        self.assertIn("img_stat opens the image", r.json["partition_table_basis"])
        self.assertIn("img_stat %s" % image, self.calls(log))
        bin_dir, _ = self.stubs("exit 1\n", img_stat="echo 'Cannot determine image type' >&2; exit 1\n")
        r = run_tool("image_layout", {"image": image}, self.dir, [bin_dir])
        self.assertEqual(r.json["partition_table"], "unknown")
        self.assertIn("img_stat did not open the image", r.json["partition_table_basis"])
        # mmls saying it itself needs no second opinion.
        bin_dir, log = self.stubs("echo 'Cannot determine partition type' >&2; exit 1\n")
        os.unlink(log)
        r = run_tool("image_layout", {"image": image}, self.dir, [bin_dir])
        self.assertIs(r.json["partition_table"], False)
        self.assertFalse([c for c in self.calls(log) if c.startswith("img_stat")])

    def test_arguments_that_are_not_an_object_are_an_answer(self):
        for raw in ("[]", "\"x\"", "7", "null"):
            r = run_tool("image_layout", None, self.dir, raw_input=raw)
            self.assertEqual(r.code, 1, raw)
            self.assertNotIn("Traceback", r.stderr)
            self.assertIn("JSON object", r.json["error"])

    def test_fat_and_empty_fields_are_read_as_what_they_are(self):
        fat = ("File System Type: FAT32\nOEM Name: MSDOS5.0\nVolume ID: 0xa1b2c3d4\n"
               "Volume Label (Boot Sector): TESTVOL\nVolume Label (Root Directory): \nSector Size: 512\nCluster Size: 4096\n")
        bin_dir, _ = self.stubs("echo 'Cannot determine partition type' >&2; exit 1\n", "cat <<'EOF'\n%sEOF\n" % fat)
        r = run_tool("image_layout", {"image": self.image()}, self.dir, [bin_dir])
        fs = r.json["partitions"][0]["filesystem"]
        self.assertEqual((fs["fs_type"], fs["volume_serial"], fs["volume_label"], fs["cluster_size"]), ("FAT32", "0xa1b2c3d4", "TESTVOL", 4096))
        # A field with no value must not take the next line for its value.
        ntfs = "File System Type: NTFS\nVolume Name: \nVolume Serial Number: 0123456789ABCDEF\nSector Size: 512\n"
        bin_dir, _ = self.stubs("echo 'Cannot determine partition type' >&2; exit 1\n", "cat <<'EOF'\n%sEOF\n" % ntfs)
        r = run_tool("image_layout", {"image": self.image()}, self.dir, [bin_dir])
        fs = r.json["partitions"][0]["filesystem"]
        self.assertNotIn("volume_label", fs)
        self.assertEqual(fs["volume_serial"], "0123456789ABCDEF")

    def test_a_partition_named_unallocated_is_still_a_partition(self):
        mmls = """GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000       0000002048   0001050623   0001048576   Unallocated space (a name the owner gave it)
"""
        bin_dir, log = self.stubs("cat <<'EOF'\n%sEOF\n" % mmls, "cat <<'EOF'\n%sEOF\n" % FSSTAT_NTFS)
        r = run_tool("image_layout", {"image": self.image()}, self.dir, [bin_dir])
        self.assertEqual([p["allocated"] for p in r.json["partitions"]], [False, False, True])
        self.assertTrue([c for c in self.calls(log) if c.startswith("fsstat") and "-o 2048" in c])

    def test_one_image_at_two_sector_sizes_keeps_both_outputs(self):
        bin_dir, _ = self.stubs("cat <<'EOF'\n%sEOF\n" % MMLS_4K, "cat <<'EOF'\n%sEOF\n" % FSSTAT_NTFS)
        image = self.image()
        first = run_tool("image_layout", {"image": image, "sector_size": 4096}, self.dir, [bin_dir]).json["raw_outputs"]
        second = run_tool("image_layout", {"image": image, "sector_size": 512}, self.dir, [bin_dir]).json["raw_outputs"]
        self.assertNotEqual(first["mmls"], second["mmls"])
        self.assertIn("mmls -b 4096", self.read(self.path(first["mmls"])))
        self.assertIn("mmls -b 512", self.read(self.path(second["mmls"])))

    def test_an_image_named_with_a_leading_dash_is_a_path_not_an_option(self):
        bin_dir, log = self.stubs("cat <<'EOF'\n%sEOF\n" % MMLS_4K, "cat <<'EOF'\n%sEOF\n" % FSSTAT_NTFS)
        self.write("-rf.img", b"\0" * 4096)
        r = run_tool("image_layout", {"image": "-rf.img"}, self.dir, [bin_dir])
        self.assertEqual(r.code, 0, r.stdout)
        calls = self.calls(log)
        self.assertIn("mmls ./-rf.img", calls)
        self.assertTrue([c for c in calls if c.startswith("fsstat") and c.endswith(" ./-rf.img")], calls)
        self.assertIn("./-rf.img", r.json["use"][0]["example"])

    def test_a_container_the_sleuth_kit_read_as_raw_has_no_offsets_to_give(self):
        mmls = "cat <<'EOF'\n%sEOF\n" % MMLS_4K
        fsstat = "cat <<'EOF'\n%sEOF\n" % FSSTAT_NTFS
        vhd = self.write("disk.vhd", b"\0" * 8192 + vhd_footer())
        # TSK 4.15 does not open a VHD: img_stat says raw, and mmls read the container's bytes.
        bin_dir, log = self.stubs(mmls, fsstat, img_stat="printf 'IMAGE FILE INFORMATION\\nImage Type: raw\\n'\n")
        r = run_tool("image_layout", {"image": vhd}, self.dir, [bin_dir])
        self.assertEqual(r.json["container"], "vhd")
        self.assertEqual(r.json["partition_table"], "unknown")
        self.assertIn("opened this vhd container as raw", r.json["partition_table_basis"])
        self.assertEqual((r.json["partitions"], r.json["use"], r.json["image_type_opened_by_sleuth_kit"]), ([], [], "raw"))
        self.assertFalse([c for c in self.calls(log) if c.startswith("fsstat")], "no file system was asked of offsets that mean nothing")
        # The same container opened as vhd: the table is the disk's.
        bin_dir, _ = self.stubs(mmls, fsstat, img_stat="printf 'IMAGE FILE INFORMATION\\nImage Type: vhd\\n'\n")
        r = run_tool("image_layout", {"image": vhd}, self.dir, [bin_dir])
        self.assertIs(r.json["partition_table"], True)
        self.assertIn("opened this vhd container as vhd", " ".join(r.json["notes"]))
        # An E01 read as ewf is the common case; a QCOW2 has no TSK reader, so raw is wrong for it too.
        e01 = self.write("a.E01", b"EVF\x09\x0d\x0a\xff\x00" + b"\0" * 4096)
        bin_dir, _ = self.stubs(mmls, fsstat, img_stat="printf 'Image Type: ewf\\n'\n")
        self.assertIs(run_tool("image_layout", {"image": e01}, self.dir, [bin_dir]).json["partition_table"], True)
        qcow = self.write("a.qcow2", b"QFI\xfb\x00\x00\x00\x03" + b"\0" * 4096)
        bin_dir, _ = self.stubs(mmls, fsstat, img_stat="printf 'Image Type: raw\\n'\n")
        r = run_tool("image_layout", {"image": qcow}, self.dir, [bin_dir])
        self.assertEqual(r.json["partition_table"], "unknown")
        self.assertIn("no reader for qcow", r.json["partition_table_basis"])
        # No answer from img_stat is not a confirmation.
        bin_dir, _ = self.stubs(mmls, fsstat, img_stat="exit 1\n")
        r = run_tool("image_layout", {"image": vhd}, self.dir, [bin_dir])
        self.assertIs(r.json["partition_table"], True)
        self.assertIn("not confirmed", " ".join(r.json["notes"]))

    def test_a_split_raw_set_starting_at_000_is_one_segment_too(self):
        bin_dir, _ = self.stubs()
        first = self.write("disk.000", b"\0" * 1024)
        self.write("disk.001", b"\0" * 1024)
        r = run_tool("image_layout", {"image": first}, self.dir, [bin_dir])
        self.assertTrue(any("one path" in n and "disk.001" in n for n in r.json["notes"]), r.json["notes"])

    @unittest.skipUnless(have("mmls"), "mmls is not on this host")
    def test_the_real_mmls_agrees_on_a_hand_built_mbr(self):
        # An MBR as the DOS partition table specification lays it out: four 16-byte entries at 446,
        # type at +4, first LBA at +8 and sector count at +12, and 0x55AA at 510.
        img = bytearray(4 * 1024 * 1024)
        entry = bytearray(16)
        entry[4] = 0x0B
        struct.pack_into("<II", entry, 8, 2048, 4096)
        img[446:462] = entry
        img[510:512] = b"\x55\xaa"
        path = self.write("mbr.img", bytes(img))
        r = run_tool("image_layout", {"image": path}, self.dir)
        self.assertIs(r.json["partition_table"], True)
        self.assertEqual([p["offset_sectors"] for p in r.json["partitions"] if p["allocated"]], [2048])
        zeros = self.write("zero.img", b"\0" * (1 << 20))
        r = run_tool("image_layout", {"image": zeros}, self.dir)
        self.assertIs(r.json["partition_table"], False)


if __name__ == "__main__":
    unittest.main()
