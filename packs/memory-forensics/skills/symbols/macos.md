---
id: symbols/macos
title: macOS memory, the kernel and its symbols, with no support claim
when: The capture is from a Mac, or you are asked whether a macOS image can be read.
needs: []
tools: [mem_profile]
requires_host: [vol]
---

Use when the capture comes from macOS. Not for the Windows and Linux symbol rules (`triage/volatility-symbols`) or the plugin lists by operating system (`triage/volatility-plugins`).

This pack makes no support claim for any macOS version, 13 to 26 included. It supplies no macOS ISF set and no converter, and `vol` listing a macOS plugin does not show that the captured kernel is supported. Where no matching ISF is set, the rule of `triage/volatility-symbols` holds: no ISF set, no support claim, and the symbol-dependent analysis is reported as not performed.

**What to establish, in this order.**
1. **Capture method.** The tool, its version, and how it ran, from the acquisition record (`acquire/images`). A method is not named from the file.
2. **Darwin kernel identity.** The kernel's own version string and build, found in the image and recorded as an observation with its offset (`strings/discipline`). `mem_profile` counts the text "Darwin Kernel Version" in its sample as an operating-system hint ("macOS or iOS"); that is a signature count, not an identity.
3. **Intel against Apple silicon.** Unverified here: no capture of either was run against this pack. Do not carry a statement made for one over to the other, and do not infer the architecture from the version.
4. **ISF provenance.** A table must match the exact kernel build and architecture and be made from matching debug material that the case or the operator supplies. For a supplied table record its source, the converter and its version, the table's identity and digest, the URI Volatility selected, the validation result and any duplicate identity, as `triage/volatility-symbols` says. A table for a nearby build is not a substitute.

When no matching table exists, report the macOS analysis that needs symbols as unexamined, and say what was done without them (strings, YARA, carving: `triage/no-framework`) and what those cannot show.

**Shows.** The kernel identity as found, the capture method, and which table, if any, was validated against it.

**Does not show.** That any macOS version, 13 to 26 included, is supported; that Intel results hold for Apple silicon; that a banner in the image means a matching table exists.

Record: the capture method; the kernel string, its offset and the architecture as established or "unverified"; the ISF's provenance, or "no ISF: unexamined".
Sensitive output: none here; a symbol table is not a secret, but it stays local-only and never goes into a job's output or a thread.
