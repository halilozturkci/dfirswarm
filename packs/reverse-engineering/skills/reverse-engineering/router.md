---
id: reverse-engineering/router
title: Reverse engineering notes by question
when: Pick a reverse engineering note when none is listed, or you cannot choose.
router: true
needs: []
tools: []
requires_host: []
---

Use when the index shows only this line and you need a reverse engineering note. Not for rules: each note holds its own.

Start
`triage/quarantine` handling a recovered sample

Executables
`pe/structure` Windows executable, DLL, driver
`pe/signature-and-resources` PE exports, signing, version information
`elf/structure` Linux executable, shared object, core
`elf/packing-and-identity` ELF packing, linking, build identity
`macho/structure` Mach-O file, universal binary
`managed/clr` managed assembly, application bundle

Code and packing
`code/static-inspection` native code, functions, references
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
`scripts/static-analysis` PowerShell, JavaScript, VBScript

Rules
`rules/yara` reading a rule hit
`rules/authoring` writing and testing a rule
