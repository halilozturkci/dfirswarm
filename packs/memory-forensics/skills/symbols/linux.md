---
id: symbols/linux
title: A Linux kernel's symbol table, matched exactly
when: A Linux capture needs an ISF, or someone offers a nearby kernel's table.
needs: []
tools: [isf_intake, vol_readiness]
requires_host: [vol, dwarf2json]
---

Use when the capture is from Linux and symbol-dependent plugins are wanted. Not for the Windows symbol rule or a missing table in general (`triage/volatility-symbols`) or for macOS (`symbols/macos`).

A Linux ISF must be made for the exact kernel build, with its architecture. A nearby release, another compiler or another distribution's kernel is not a substitute (`triage/volatility-plugins`).

**Establish, in this order.**
1. **The image's banner and architecture.** `vol_readiness` (view `symbols`) finds the banners in the image with `vol`'s `banners.Banners` and matches each against the identifier column of `isfinfo` ("Identifying information"), equal once the line end and NULs that follow a banner are taken off. If that column is not there, the view is unknown. Record the banner's offset and the architecture as found, never as the file name says.
2. **Matching debug material.** The case or the operator supplies the kernel's vmlinux or debug-symbols file for that build. A System.map holds addresses and no types, so its table has no banner and cannot be ready.
3. **The conversion.** `isf_intake` runs `dwarf2json` on that file, records the converter's version and argv, and says `ready` only if the produced table's `linux_banner` is a banner found in the image and the build identity agrees. Any other table is removed. The pack pins `dwarf2json` 0.9.0 for amd64 only (the project publishes no arm64 build): where it is not installed the tool fails with verdict `blocked`, and the report says the table was not made.
4. **Validation.** Record the table's source, the converter and its version, its sha256 and the URI Volatility selected, as `triage/volatility-symbols` says. A table is local-only. `isf_intake`'s table is the one permitted exception in a job's output ($OUT, where the tool contract has it write): copy it to the local symbols directory and remove it from $OUT before any report package or thread.

**Shows.** That a table exists whose banner is, exactly, a banner found in the image.

**Does not show.** That the examination will work; that the running kernel is that banner's, when the image holds several; that any kernel version is supported; anything about macOS.

Record: the banner (release word only in a post) and its offset, the architecture, the debug material's source, the converter, the table's identity and digest, the verdict of `isf_intake` and of `vol_readiness`.
**A program that left a process.** A Volatility or dwarf2json that leaves a process running makes `vol_readiness` and `isf_intake` `partial` (`program_group`); `isf_intake` then keeps no table.

Sensitive output: none here; a symbol table is not a secret, but it stays local-only: out of a thread and a report package, and out of a job's output except the one table `isf_intake` writes there (above).
