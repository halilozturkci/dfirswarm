---
id: macho/structure
title: Mach-O files and universal binaries
when: The sample is a Mach-O executable, library, bundle or universal binary.
needs: [triage/quarantine]
tools: [pe_info]
requires_host: [r2]
---

Use when the sample is a Mach-O or a universal ("fat") binary. Not for macOS trust or notarisation decisions, or for what the program did.

1. **A universal binary is several binaries.** `pe_info` lists every slice in `slices` with `cpu_type_name`, `offset`, `size` and its own `status`; `slices_read_in_full` against `slices_declared` says whether all were read. Report per slice. Capabilities, libraries and entry points can differ between slices: never write one conclusion for the file.
2. **Preserve each slice as its own object.** Cut it by byte range in a job (`r2 -N -n -q -c "wtf $OUT/slice0.bin SIZE @ OFFSET" SAMPLE 2> "$OUT/slice0.err"`: `-n` reads the file raw, so the address is the file offset; check `wtf?` on your version), hash the original and the slice, and record the range. `r2` opens one slice: state which one (`r2 -h` lists `-a` and `-b`).
3. **Header and entry.** Read `type` (executable, dylib, bundle, kext), byte order and width from the slice's `macho`. `entry_offset` is the `LC_MAIN` file offset into the `__TEXT` segment; a file with `LC_UNIXTHREAD` instead has no `LC_MAIN` entry here. Locators carry their type: file offset, or virtual address from `segments`.
4. **Linked libraries** (`linked_libraries`, `linked_library_commands`) are what the loader is asked for: a weak, re-exported or lazy-loaded library is a different command, and `@rpath`, `@loader_path` and relative names are resolution leads that need the examined system's search paths. System frameworks are ordinary. Install names are claims; a library name is not a use.
5. **`LC_CODE_SIGNATURE`** is read as presence, offset and size only (`code_signature`). Nothing here verifies a signature, a team identity or a notarisation ticket; write "not verified". An `LC_ENCRYPTION_INFO` command (it appears in `commands`) can mean a segment is encrypted and unreadable statically; this pack does not decode its fields, so say the segment contents were not read.
6. **Not read**: symbol tables, dyld information, sections inside segments, segment contents. Strings and code are separate steps (`strings/obfuscated`, `code/static-inspection`).
7. Execution, persistence and install artefacts belong to the macOS pack: link to it only if it is loaded (check the run's tool inventory).

Sensitive output: an install name or a library path can carry user-info or a token; `pe_info` withholds those (`withheld_fields` names them with their offsets): cite the offset.

Shows: slices, header fields, load commands, linked libraries, segments, signature location. Does not show: signature validity, what any slice does, that all slices behave alike. Record: `pe_info` status, problems, per-slice coverage, ranges and hashes, what was not read.
