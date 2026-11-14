---
id: elf/structure
title: An ELF file and the loader's view
when: The sample is a Linux or BSD executable, shared object or core file.
needs: [triage/quarantine]
card: elf_directories ({"path": "<sample>"}) has the tables program_headers, dynamic, dynsym, symtab and notes; a table longer than limit is whole in the file all_results names, and coverage lists what it did not read. Read status, problems and coverage in the pe_info answer first. The loader acts on program headers; section_headers_absent true makes stripped null: not determined. An empty needed_libraries with dynamic.source null is not proof of static linking. Never run ldd on an untrusted file. A withheld path is in withheld_fields with its file_offset: cite the offset. Does not show: behaviour; a library name is not observed use.
tools: [pe_info, entropy_map, elf_directories]
requires_host: [readelf]
---

Use when the sample is an ELF executable, shared object or core. Not for what the program does, or for a core file's memory (its notes and mappings need a core-aware reader).

Read `status`, `problems` and `coverage` in the `pe_info` answer first.

1. **Header.** Class, byte order, machine, type, entry. `type: shared object` does not separate a library from a position-independent executable. `interpreter` and a nonzero `entry_point` are leads, not a test (a C library can carry both); `readelf -d SAMPLE` shows `FLAGS_1 ... PIE` where the linker set it. Record which you relied on.
2. **Two views.** The loader acts on program headers (`segments`). Section headers are optional at run time and can be absent, removed or inconsistent: keep disagreements as evidence. `section_headers_absent` true makes `stripped` null: symbol removal is not determined. `stripped` is true only when sections exist and none is a symbol table (a stripped file keeps its dynamic symbols). `entropy_map` profiles the whole file.
3. **Dependencies** come from the dynamic array read through `PT_DYNAMIC`: `needed_libraries`, `soname`, `rpath`, `runpath`, and `dynamic.source`, which names the view used. An empty list with `dynamic.source` null is not proof of static linking. Cross-check with `readelf -d SAMPLE`. A path that carries user-info or a query value is withheld and listed in `withheld_fields` with its `file_offset`: cite the offset. Never run `ldd` on an untrusted file: it can run the file's loader.
4. A library name suggests a possible function, not observed network use. Read imported symbols and relocations with `readelf --dyn-syms -W SAMPLE` and `readelf -r -W SAMPLE`, as declared names and not as calls; `elf_directories` has the tables `program_headers`, `dynamic` (every tag; `flags_1`, `bind_now`), `dynsym`, `symtab` (found only through a section header: a stripped file has none) and `notes` (`notes.gnu_build_id`), with `stack_executable` and `gnu_relro`. A table longer than `limit` is whole in the file `all_results` names; `coverage` lists what it did not read (sections, relocations, symbol versions, DWARF).

Only if the question is packing, static linking, search paths or build identity, read `elf/packing-and-identity`.

Shows: header, loader view, declared dependencies. Does not show: behaviour, symbol removal when sections are absent, symbols and notes (`elf_directories` reads them). Record: status, problems, `limits_hit`, which view supplied the dependencies, offsets.
