---
id: processes/kernel-integrity
title: Comparing module, driver and kernel views
when: Kernel views disagree, or someone asks whether the kernel was tampered with.
needs: []
tools: []
requires_host: [vol]
---

Use when two views of kernel objects disagree, or you are asked about hidden modules or drivers. Not for code injected into a user process (`processes/injection`) or for choosing plugins (`triage/volatility-plugins`).

**Compare views, not plugins.** On Windows the module list (`windows.modules`), a scan for module structures (`windows.modscan`), the driver objects (`windows.driverscan`) and the unloaded modules (`windows.unloadedmodules`) each read a different structure. On Linux `linux.lsmod` and `linux.check_modules` do. Verify the names in the image you have (`vol --help`): plugin output and names change between versions (`triage/volatility-plugins`).

**Decision rules.**
1. A discrepancy is a question, not a finding. Name each reading it allows: a stale object (freed memory a scan still finds), an object unlinked or relinked while the capture ran (smear), a page that was not captured, a module that unloaded, or a symbol table that does not fit the kernel.
2. **Stale objects.** A scan finds remnants of freed memory; their fields and times are what the old object held. A driver that loaded and unloaded is ordinary.
3. **Unloaded components.** The unloaded list keeps a short history of names and address ranges. It shows that something was loaded at some time, not what it did.
4. **Smear.** A list walked while the system ran can cross a load or an unload. Read the same view again, or from a second capture, before comparing.
5. **Symbol errors.** A plugin that fails or prints nothing because of a symbol or layer error did not examine (`triage/coverage`). A table for the wrong kernel can print plausible wrong output; establish the kernel's identity first (`triage/volatility-symbols`).
6. **No rootkit from a discrepancy alone.** Report the discrepancy, the readings you ruled out and in, and what would tell them apart: the second view, the module's file on disk and its hash, its signature, its times. A verdict of tampering needs evidence beyond a difference between two lists.

**Shows.** Which views agree and disagree, for which objects, and which readings remain.

**Does not show.** That a module missing from one list is hidden; that a driver in a scan only is malicious; that no discrepancy means the kernel is unmodified.

Record: the image's hash, the kernel's identity and the table used, each plugin with its version and options, the objects that differ with their addresses, and the readings kept.
Sensitive output: addresses, names and counts only; a region dumped from a module runs as a job with `secret_output: true` (`processes/preserve-regions`).
