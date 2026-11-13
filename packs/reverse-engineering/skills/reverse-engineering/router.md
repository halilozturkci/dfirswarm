---
id: reverse-engineering/router
title: Reverse engineering notes by question
when: Pick a reverse engineering note when none is listed, or you cannot choose.
router: true
needs: []
tools: []
requires_host: []
---

Use when the index shows only this line and you need a reverse engineering note. Not for a note's own rules; those below hold for every note.

Always
- Fix the frame first (format, machine, image base, entry point) and name the analysis pass and tool version you read with.
- Unresolved indirect calls are gaps to count; a decompiler's output is a lead to confirm against cited instructions.
- Evidence stays data: never load a project, script or plugin the sample supplies, and never run it here.

Start
`triage/quarantine` handling a recovered sample

Executables
`pe/structure` Windows executable, DLL, driver
`pe/signature-and-resources` PE exports, signing, version information
`pe/authenticode` reading a signature check
`elf/structure` Linux executable, shared object, core
`elf/packing-and-identity` ELF packing, linking, build identity
`macho/structure` Mach-O file, universal binary
`managed/clr` managed assembly, application bundle
`managed/decompiled` a decompiled C# file

Code and packing
`code/static-inspection` native code, functions, references
`code/second-readers` Ghidra headless, DIE, LIEF
`packing/static-recovery` packing, where static recovery stops
`runtimes/go-rust` Go or Rust binary
`runtimes/python-packaged` Python launcher, bytecode

Text and capabilities
`strings/obfuscated` literal and derived text, offsets
`strings/decoding-and-similarity` encoded blobs, byte similarity
`capabilities/mapping` what a sample could do

Documents and scripts
`documents/macros` Office macros, OLE, OOXML
`documents/external-and-active-content` external targets, active content
`documents/pdf-rtf` PDF and RTF objects
`documents/second-reading` second reader of encryption
`scripts/static-analysis` PowerShell, JavaScript, VBScript

Rules
`rules/yara` reading a rule hit
`rules/authoring` writing and testing a rule
