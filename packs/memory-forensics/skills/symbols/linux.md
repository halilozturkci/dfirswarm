---
id: symbols/linux
title: A Linux kernel's symbol table, matched exactly
when: A Linux capture needs an ISF, or someone offers a nearby kernel's table.
needs: []
tools: [isf_intake, vol_readiness]
requires_host: [vol]
---

Use when the capture is from Linux and symbol-dependent plugins are wanted. Not for the Windows symbol rule or a missing table in general (`triage/volatility-symbols`) or for macOS (`symbols/macos`).

A Linux ISF must be made for the exact kernel build, with its architecture. A nearby release, another compiler or another distribution's kernel is not a substitute, and no public cache covers it (`triage/volatility-plugins`).

**Establish, in this order.**
1. **The image's banner and architecture.** `vol_readiness` (view `symbols`) finds the banners in the image with `banners.Banners` and matches each, character for character, against the banner columns of `isfinfo`. Record the banner's offset and the architecture as found, never as the file name says.
2. **Matching debug material.** The case or the operator supplies the kernel's vmlinux or debug-symbols file for that build. A System.map holds addresses and no types, so its table has no banner and cannot be ready.
3. **The conversion.** `isf_intake` runs `dwarf2json` on that file, records the converter's version and argv, and says `ready` only if the produced table's `linux_banner` is a banner found in the image and the build identity agrees. Any other table is removed. The pack does not yet declare `dwarf2json`: where it is not installed the tool fails with verdict `blocked`, and the report says the table was not made.
4. **Validation.** Record the table's source, the converter and its version, its sha256 and the URI Volatility selected, as `triage/volatility-symbols` says. A table is local-only: it never goes into a thread or a report package.

**Shows.** That a table exists whose banner is, exactly, a banner found in the image.

**Does not show.** That the examination will work; that the running kernel is that banner's, when the image holds several; that any kernel version is supported; anything about macOS.

Record: the banner (release word only in a post) and its offset, the architecture, the debug material's source, the converter, the table's identity and digest, the verdict of `isf_intake` and of `vol_readiness`.
Sensitive output: none here; a symbol table is not a secret, but it stays local-only and never goes into a job's output or a thread.
