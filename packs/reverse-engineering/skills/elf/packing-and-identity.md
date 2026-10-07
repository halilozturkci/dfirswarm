---
id: elf/packing-and-identity
title: ELF packing, linking and build identity
when: You must say whether an ELF is packed, how it links or which build it is.
needs: []
tools: []
requires_host: [readelf, upx]
---

Use when the question is packing, static linking, library search paths or build identity. Not for running anything: no loader, no runtime unpacking.

- **Packing** is a hypothesis: section names, entropy and a sparse import list can each be absent or misleading. If `upx -t` on a copy recognises the file, decompress only a derived copy: `upx -d -o "$OUT/<name>.upx-d" SAMPLE` in a job, never without `-o` (UPX rewrites its input in place); record the UPX version, its diagnostics, both hashes and the derivation, and read both forms. A failure does not show the file is unpacked. If static recovery is incomplete, keep the original and name what stayed inaccessible.
- **Static linking** is common in legitimate software, including some Go and Rust builds. It says nothing of provenance, and a static file is not a "dropped tool" for that reason. Say what `PT_INTERP` and the dynamic array show, and no more.
- **RPATH, RUNPATH and preload settings** are resolution leads. Expand them against the examined system, check ownership and permissions, then identify the object they name; the setting alone does not show another library was loaded.
- **Build ID** is a linker-written note (`readelf -n SAMPLE`), kept in stripped files of one build and in separate debug files. A rebuild may change it, a later edit may leave it, and it can be set by hand: use it to find candidate related builds, never to prove identity or equivalence.

Shows: markers for a hypothesis, and where a build ID sits. Does not show: that a file is packed or malicious, or what was loaded. Record: tool versions, hashes of the original and the derived file, the raw build-ID bytes beside the SHA-256.
