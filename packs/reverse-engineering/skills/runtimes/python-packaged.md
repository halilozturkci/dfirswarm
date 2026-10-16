---
id: runtimes/python-packaged
title: Python-packaged applications and bytecode
when: An executable looks like a launcher for bundled Python code.
needs: [triage/quarantine]
tools: [pe_info, pe_directories]
requires_host: [strings, capa, r2]
---

Use when a PE or ELF looks like a bootloader around bundled Python: a Python runtime library among its imports or strings, a large overlay, a big RCDATA resource. Not for importing, unmarshalling or running anything recovered.

1. **Separate the bootloader from the application.** Imports, capa matches and strings of the launcher describe the launcher. Record `pe_info` `overlay_offset` and `overlay_bytes`, and for a PE the large entries of `pe_directories` `resources`; search for runtime text with `strings -a -t x SAMPLE > "$OUT/strings.txt"` (`python`, `_MEIPASS`, `pyi`, `.pyc`, `.pyd`).
2. **Name the packager from what is in the file**, not from a guess: archive markers and table-of-contents shapes are documented by each packager's own source, and they change between releases. If you compare against a documented marker, state which packager and release's documentation you used and that the file matched it at a recorded offset.
3. **Preserve before reading.** Cut the overlay or resource as a derived copy in a job: a PE resource with `pe_directories` `extract` (`resource:<row>`, with `extract_to` under `$OUT`), an overlay by byte range (`r2 -N -n -q -c "wtf $OUT/overlay.bin SIZE @ OFFSET" SAMPLE 2> "$OUT/overlay.err"`: `-n` reads the file raw; check `wtf?` on your version); hash both the original and the copy, and record the range and where it came from. A bundle that is not a ZIP is not listed by the document tools.
4. **No extractor or bytecode disassembler is declared in this pack.** Recovering modules needs a vetted archive reader and a version-aware, non-evaluating bytecode parser; supply one under the operator's control or stop and write "archive not unpacked: no reader". The marshal and pickle formats are not safe to load from untrusted data (Python's documentation says so), so never `marshal.loads`, `pickle.loads`, `import` or `exec` a recovered module, and never run the launcher to see what it unpacks.
5. **Bytecode begins with a magic number tied to the interpreter version.** Record the first bytes of a recovered `.pyc` and look the value up in that version's own source; do not infer the version from the launcher. Decompiled source is a reconstruction; the bytecode is the evidence.
6. Compiled extension modules (`.pyd`, `.so`) are native code: read them as native (`code/static-inspection`).

Sensitive output: bundled scripts often hold credentials, tokens and URLs; keep recovered content in `$OUT` of a job with `secret_output: true` and cite file, offset and length.

Shows: that a launcher and an appended archive or resource exist, where, and how big. Does not show: the application's modules, what they do, or the interpreter version. Record: ranges, hashes of original and copy, packager evidence with the documentation used, what was not unpacked.
