---
id: code/second-readers
title: Ghidra's headless route, DIE and LIEF as second readings
when: A second reader of code, signatures or structure is wanted beside the pack's tools.
needs: [triage/quarantine]
tools: [pe_info, pe_directories, elf_directories, macho_directories]
requires_host: [r2, analyzeHeadless, java, diec]
---

Use when `r2` and the pack's tools leave a question that a second program could answer: decompiled functions (Ghidra), a packer or compiler signature name (DIE) or a second parser of PE, ELF or Mach-O structure (LIEF). Not for running, emulating or patching anything, or for what the program did.

All three are declared optional and no tool of this pack runs any of them. None was observed on a real sample when it was declared: what each does here is unmeasured, so record "not run" where the image lacks one, and take its behaviour from the version it carries, not from this leaf.

1. **Ghidra, headless** (`analyzeHeadless`, release 12.2 as pinned; it needs the 64-bit JDK 21 declared as `java`). This is a method you carry out in a job, not a script the pack ships: import a copy of the sample into a project kept under `$OUT` (a fresh directory per sample, never the sample's own directory), analyse it without the GUI, and read decompiled functions and cross-references from that project. Take the option names from the release's documentation, not from this leaf.
2. **Evidence is never an extension or a script.** Install no extension, and load no script, plugin or rule file that the sample, its container or its directory supplies. A script you write yourself lives under `$OUT` with its text and SHA-256 recorded. The project holds derived analysis, not observation; the original stays untouched and hashed.
3. **Name the analysis.** Which analyzers ran is a setting, as with `r2` (`code/static-inspection`): record the Ghidra and JDK versions, the options and the time limit. A function found, a reference found and "no reference" depend on that setting.
4. **A decompilation is a reconstruction**, a lead until you cite instructions at addresses. It can carry string literals: keep it under `$OUT` in a job with `secret_output: true`.
5. **`diec`** (Detect It Easy 3.21 as pinned; upstream publishes no Linux arm64 build, so an arm64 image records it as not installed) names the packer, protector, compiler and linker signatures it recognises. A match is a hypothesis and a miss shows nothing; record its version and the signature database's (`packing/static-recovery`).
6. **`lief`** (a Python library, 1.0.0 as pinned): use it in a short parser you write under `$OUT`, reading the sample as data, and compare its reading with `pe_info`, `pe_directories`, `elf_directories` and `macho_directories`. Where two parsers disagree, record both readings; neither is taken as right. This leaf says nothing of what LIEF checks or leaves out.

Sensitive output: decompiled text and project files can hold credentials; keep them under `$OUT`, cite address and length, never a value, a fragment or a hash.

Shows: a second reading, under a named setting. Does not show: execution, intent, that a signature match is the packer, or that two parsers agreeing is correct. Record: program and library versions, options, the project path, the files, the disagreements.
