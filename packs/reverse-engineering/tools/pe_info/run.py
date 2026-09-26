#!/usr/bin/env python3
"""Read an executable's structure from its bytes, and never run it.

What a binary asks the operating system for is the cheapest capability list an
examiner gets, and it is in the headers. Three readings matter more than the
rest:

    the section table   raw size far below virtual size, with high entropy, is a
                        packer: the real code only exists once it unpacks itself
    the imports         WININET or WS2_32 is network; CreateRemoteThread with
                        WriteProcessMemory and VirtualAllocEx is injection; and
                        a binary with almost no imports and one LoadLibrary is
                        resolving them at runtime to hide exactly this
    the timestamp       attacker-controllable, and useful for that reason: one in
                        the future, or identical across a family, is the finding

Formats read here: PE (32 and 64 bit), ELF, and Mach-O far enough to list the
libraries it links. All of it is parsing; nothing is executed, and under
--quarantine the kernel would refuse anyway.
"""
import datetime
import json
import math
import mmap
import os
import struct
import sys

MACHINES = {0x014c: "i386", 0x8664: "x86-64", 0x01c0: "ARM", 0xaa64: "ARM64", 0x0200: "IA64"}
SUBSYSTEMS = {1: "native", 2: "GUI", 3: "console", 9: "Windows CE", 10: "EFI application",
              12: "EFI runtime driver", 14: "Xbox"}
SECTION_FLAGS = [(0x20000000, "execute"), (0x40000000, "read"), (0x80000000, "write"),
                 (0x00000020, "code"), (0x00000040, "initialised data"),
                 (0x00000080, "uninitialised data"), (0x02000000, "discardable")]
ELF_TYPES = {1: "relocatable", 2: "executable", 3: "shared object", 4: "core"}
ELF_MACHINES = {0x03: "i386", 0x3e: "x86-64", 0x28: "ARM", 0xb7: "AArch64", 0xf3: "RISC-V"}
MACHO_TYPES = {1: "object", 2: "executable", 6: "dylib", 8: "bundle", 4: "core"}


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def entropy(block):
    if not block:
        return 0.0
    counts = [0] * 256
    for byte in block:
        counts[byte] += 1
    out, total = 0.0, len(block)
    for count in counts:
        if count:
            p = count / total
            out -= p * math.log2(p)
    return round(out, 3)


def cstring(blob, at, end=None):
    """Read a complete C string, bounded by its file-backed container."""
    end = len(blob) if end is None else min(len(blob), end)
    nul = blob.find(b"\x00", at, end)
    if nul >= 0:
        end = nul
    return blob[at:end].decode("utf-8", "replace")


def when(stamp):
    if not stamp:
        return None
    try:
        return datetime.datetime.fromtimestamp(
            stamp, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def read_pe(blob, with_imports):
    out = {"format": "PE"}
    if len(blob) < 0x40:
        return {"format": "PE", "error": "shorter than a DOS header"}
    pe_at, = struct.unpack_from("<I", blob, 0x3C)
    if pe_at + 24 > len(blob) or blob[pe_at:pe_at + 4] != b"PE\x00\x00":
        return {"format": "PE", "error": "no PE signature where the DOS header points"}
    machine, sections, stamp, _sym, _nsym, opt_size, characteristics = struct.unpack_from(
        "<HHIIIHH", blob, pe_at + 4)
    out.update({
        "machine": MACHINES.get(machine, hex(machine)),
        "sections_declared": sections,
        "compile_timestamp": when(stamp),
        "compile_timestamp_raw": stamp,
        "characteristics": hex(characteristics),
        "is_dll": bool(characteristics & 0x2000),
        "is_system_file": bool(characteristics & 0x1000),
    })
    opt_at = pe_at + 24
    if opt_size and opt_at + 2 <= len(blob):
        magic, = struct.unpack_from("<H", blob, opt_at)
        wide = magic == 0x20b
        out["bits"] = 64 if wide else 32
        try:
            out["entry_point"] = hex(struct.unpack_from("<I", blob, opt_at + 16)[0])
            out["image_base"] = hex(struct.unpack_from("<Q" if wide else "<I", blob,
                                                       opt_at + (24 if wide else 28))[0])
            out["subsystem"] = SUBSYSTEMS.get(struct.unpack_from("<H", blob, opt_at + 68)[0],
                                              "unknown")
            dll_flags = struct.unpack_from("<H", blob, opt_at + 70)[0]
            out["aslr"] = bool(dll_flags & 0x0040)
            out["dep"] = bool(dll_flags & 0x0100)
            dirs_at = opt_at + (112 if wide else 96)
            count, = struct.unpack_from("<I", blob, opt_at + (108 if wide else 92))
            directories = []
            for i in range(min(count, 16)):
                rva, size = struct.unpack_from("<II", blob, dirs_at + i * 8)
                directories.append({"index": i, "rva": rva, "size": size})
            out["signed"] = bool(len(directories) > 4 and directories[4]["size"])
        except struct.error:
            directories = []
            out["header_problem"] = "the optional header is shorter than it claims"
    else:
        directories = []

    table_at = opt_at + opt_size
    parsed, rva_map = [], []
    for i in range(sections):
        at = table_at + i * 40
        if at + 40 > len(blob):
            break
        name = blob[at:at + 8].rstrip(b"\x00").decode("utf-8", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", blob, at + 8)
        flags, = struct.unpack_from("<I", blob, at + 36)
        body = blob[rawptr:min(len(blob), rawptr + rawsize)] if rawptr and rawsize else b""
        entry = {"name": name, "virtual_size": vsize, "virtual_address": hex(vaddr),
                 "raw_size": rawsize, "raw_pointer": rawptr,
                 "entropy": entropy(body),
                 "permissions": [n for bit, n in SECTION_FLAGS if flags & bit]}
        if rawsize and vsize > rawsize * 4 and entry["entropy"] > 7.0:
            entry["packed_shape"] = True
        if "write" in entry["permissions"] and "execute" in entry["permissions"]:
            entry["writable_and_executable"] = True
        parsed.append(entry)
        rva_map.append((vaddr, vsize or rawsize, rawptr, rawsize))
    out["sections"] = parsed

    def to_file_range(rva):
        """Map an RVA only into bytes actually present in its section."""
        for vaddr, vsize, rawptr, rawsize in rva_map:
            delta = rva - vaddr
            if 0 <= delta < min(max(vsize, 1), rawsize):
                start = rawptr + delta
                return start, min(len(blob), rawptr + rawsize)
        return None

    def to_offset(rva):
        mapped = to_file_range(rva)
        return mapped[0] if mapped else None

    imports = []
    if with_imports and len(directories) > 1 and directories[1]["size"]:
        at = to_offset(directories[1]["rva"])
        max_descriptors = directories[1]["size"] // 20
        terminated = False
        for index in range(max_descriptors):
            if at is None or at + index * 20 + 20 > len(blob):
                out["import_table_problem"] = "the import directory points outside file-backed bytes"
                break
            fields = struct.unpack_from("<IIIII", blob, at + index * 20)
            if not any(fields):
                terminated = True
                break
            original_thunk, _t, _f, name_rva, first_thunk = fields
            name_range = to_file_range(name_rva)
            library = cstring(blob, name_range[0], name_range[1]) if name_range else "?"
            names = []
            thunk_range = to_file_range(original_thunk or first_thunk)
            thunk_at = thunk_range[0] if thunk_range else None
            thunk_end = thunk_range[1] if thunk_range else None
            wide = out.get("bits") == 64
            step = 8 if wide else 4
            thunk_terminated = False
            while thunk_at is not None and thunk_at + step <= thunk_end:
                value = struct.unpack_from("<Q" if wide else "<I", blob, thunk_at)[0]
                if not value:
                    thunk_terminated = True
                    break
                ordinal_bit = 1 << (63 if wide else 31)
                if value & ordinal_bit:
                    names.append("#%d" % (value & 0xFFFF))
                else:
                    hint_range = to_file_range(value)
                    if hint_range is not None:
                        names.append(cstring(blob, hint_range[0] + 2, hint_range[1]))
                thunk_at += step
            entry = {"library": library, "functions": names, "function_count": len(names)}
            if thunk_range is None:
                entry["thunk_table_problem"] = "the thunk RVA is not backed by file bytes"
            elif not thunk_terminated:
                entry["thunk_table_problem"] = "the thunk table has no terminator in its section"
            imports.append(entry)
        if max_descriptors and not terminated and len(imports) == max_descriptors:
            out["import_table_problem"] = "the import directory has no terminating descriptor"
        out["imports"] = imports
        out["import_library_count"] = len(imports)
        if len(imports) <= 2 and sum(i["function_count"] for i in imports) <= 6:
            out["few_imports"] = ("Almost nothing is imported. A binary that resolves its imports "
                                  "at runtime looks like this, and so does a packed one.")
    if len(directories) > 0 and directories[0]["size"]:
        at = to_offset(directories[0]["rva"])
        if at is not None and at + 40 <= len(blob):
            name_rva, = struct.unpack_from("<I", blob, at + 12)
            name_range = to_file_range(name_rva)
            if name_range is not None:
                out["export_name"] = cstring(blob, name_range[0], name_range[1])
    return out


def read_elf(blob):
    out = {"format": "ELF"}
    if len(blob) < 64:
        return {"format": "ELF", "error": "shorter than an ELF header"}
    wide = blob[4] == 2
    little = blob[5] == 1
    end = "<" if little else ">"
    out["bits"] = 64 if wide else 32
    out["endian"] = "little" if little else "big"
    elf_type, machine = struct.unpack_from(end + "HH", blob, 16)
    out["type"] = ELF_TYPES.get(elf_type, str(elf_type))
    out["machine"] = ELF_MACHINES.get(machine, hex(machine))
    if wide:
        entry, phoff, shoff = struct.unpack_from(end + "QQQ", blob, 24)
        phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from(end + "HHHHH", blob, 54)
    else:
        entry, phoff, shoff = struct.unpack_from(end + "III", blob, 24)
        phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from(end + "HHHHH", blob, 42)
    out["entry_point"] = hex(entry)
    out["program_headers"] = phnum
    out["section_headers"] = shnum
    out["stripped"] = shnum == 0

    segments = []
    for i in range(phnum):
        at = phoff + i * phentsize
        if at + phentsize > len(blob):
            break
        try:
            if wide:
                p_type, flags, offset, vaddr, _paddr, file_size, mem_size, align = struct.unpack_from(
                    end + "IIQQQQQQ", blob, at)
            else:
                p_type, offset, vaddr, _paddr, file_size, mem_size, flags, align = struct.unpack_from(
                    end + "IIIIIIII", blob, at)
        except struct.error:
            break
        body = blob[offset:min(len(blob), offset + file_size)] if file_size else b""
        segments.append({
            "index": i,
            "type": p_type,
            "offset": offset,
            "virtual_address": hex(vaddr),
            "file_size": file_size,
            "memory_size": mem_size,
            "permissions": {
                "read": bool(flags & 0x4),
                "write": bool(flags & 0x2),
                "execute": bool(flags & 0x1),
            },
            "alignment": align,
            "entropy": entropy(body),
        })
    out["segments"] = segments

    sections, names_blob = [], b""
    if shnum and shoff and shstrndx < shnum:
        at = shoff + shstrndx * shentsize
        if at + shentsize <= len(blob):
            if wide:
                str_off, str_size = struct.unpack_from(end + "QQ", blob, at + 24)
            else:
                str_off, str_size = struct.unpack_from(end + "II", blob, at + 16)
            names_blob = blob[str_off:str_off + str_size]
    for i in range(shnum):
        at = shoff + i * shentsize
        if at + shentsize > len(blob):
            break
        name_off, sh_type = struct.unpack_from(end + "II", blob, at)
        if wide:
            flags, addr, offset, size = struct.unpack_from(end + "QQQQ", blob, at + 8)
        else:
            flags, addr, offset, size = struct.unpack_from(end + "IIII", blob, at + 8)
        name = cstring(names_blob, name_off) if names_blob else str(i)
        body = blob[offset:min(len(blob), offset + size)] if sh_type != 8 else b""
        sections.append({"name": name, "type": sh_type, "address": hex(addr),
                         "offset": offset, "size": size, "entropy": entropy(body),
                         "executable": bool(flags & 0x4), "writable": bool(flags & 0x1)})
    out["sections"] = sections

    needed = []
    by_name = {s["name"]: s for s in sections}
    dynamic, dynstr = by_name.get(".dynamic"), by_name.get(".dynstr")
    if dynamic and dynstr:
        strings = blob[dynstr["offset"]:dynstr["offset"] + dynstr["size"]]
        step = 16 if wide else 8
        at = dynamic["offset"]
        for _ in range(dynamic["size"] // step):
            if at + step > len(blob):
                break
            if wide:
                tag, value = struct.unpack_from(end + "qQ", blob, at)
            else:
                tag, value = struct.unpack_from(end + "iI", blob, at)
            if tag == 0:
                break
            if tag == 1:
                needed.append(cstring(strings, value))
            elif tag in (15, 29):
                out["rpath" if tag == 15 else "runpath"] = cstring(strings, value)
            at += step
    out["needed_libraries"] = needed
    return out


def read_macho(blob):
    out = {"format": "Mach-O"}
    magic = blob[:4]
    if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        # A fat binary holds several architectures end to end. Read the first slice
        # rather than stopping here, and say that is what happened.
        try:
            count, = struct.unpack_from(">I", blob, 4)
            slices = []
            for i in range(count):
                cpu, sub, offset, size, align = struct.unpack_from(">IIIII", blob, 8 + i * 20)
                slices.append({"cpu_type": hex(cpu), "offset": offset, "bytes": size})
            if slices:
                inner = read_macho(blob[slices[0]["offset"]:slices[0]["offset"] + slices[0]["bytes"]])
                inner["format"] = "Mach-O universal binary"
                inner["architectures"] = slices
                inner["read_slice"] = 0
                inner["slice_note"] = ("A fat binary holds several architectures; the first slice "
                                       "was read. The others may differ, and a sample can carry a "
                                       "payload in only one of them.")
                return inner
        except struct.error:
            pass
        return {"format": "Mach-O universal binary",
                "note": "a fat binary whose architecture table could not be read"}
    wide = magic == b"\xcf\xfa\xed\xfe"
    out["bits"] = 64 if wide else 32
    cputype, _sub, filetype, ncmds, _size, flags = struct.unpack_from("<IIIIII", blob, 4)
    out["cpu_type"] = hex(cputype)
    out["type"] = MACHO_TYPES.get(filetype, str(filetype))
    out["load_commands"] = ncmds
    at = 32 if wide else 28
    libraries, segments = [], []
    for _ in range(ncmds):
        if at + 8 > len(blob):
            break
        cmd, size = struct.unpack_from("<II", blob, at)
        if size < 8 or at + size > len(blob):
            break
        if cmd in (0x0c, 0x0d, 0x18, 0x1f):          # LOAD_DYLIB and friends
            offset, = struct.unpack_from("<I", blob, at + 8)
            libraries.append(cstring(blob, at + offset, at + size))
        elif cmd in (0x01, 0x19):                    # SEGMENT, SEGMENT_64
            segments.append(blob[at + 8:at + 24].rstrip(b"\x00").decode("utf-8", "replace"))
        at += size
    out["linked_libraries"] = libraries
    out["segments"] = segments
    return out


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a PE, ELF or Mach-O file")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    with_imports = args.get("with_imports", True)

    with open(path, "rb") as fh:
        try:
            blob = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:
            fail("the file is empty", path=path)
        try:
            head = blob[:4]
            if head[:2] == b"MZ":
                body = read_pe(blob, with_imports)
            elif head == b"\x7fELF":
                body = read_elf(blob)
            elif head in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
                body = read_macho(blob)
            else:
                fail("this is not a PE, ELF or Mach-O file", path=path, head_hex=head.hex(),
                     note="file_type will say what it is instead")
        finally:
            blob.close()

    print(json.dumps({
        "path": path, "bytes": os.path.getsize(path), **body,
        "note": "Nothing here was executed. A section whose virtual size is far larger than its "
                "raw size, with entropy near 8, is packed and its disassembly is meaningless until "
                "it is unpacked. Imports are capability by declaration: pair them with capa, which "
                "reads the code instead.",
    }, indent=2))


if __name__ == "__main__":
    main()
