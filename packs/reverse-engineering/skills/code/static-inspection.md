---
id: code/static-inspection
title: Reading native code with its analysis limits stated
when: You must read a native binary's code: functions, control flow, references.
needs: [triage/quarantine]
tools: [pe_info, pe_directories]
requires_host: [r2]
---

Use when you must read the code of a PE, ELF or Mach-O file with `r2`. Not for saying what the program did, who wrote it or why, and not for running, emulating or patching it.

1. **Fix the frame first.** From `pe_info` (and `pe_directories` for a PE) record format, machine, bits, byte order, image base and the entry point with its type: an RVA in a PE, an address in an ELF, a file offset for a Mach-O `LC_MAIN`. If `r2` does not detect the architecture, give it (`r2 -h` lists `-a` and `-b`) and record that you did.
2. **An analysis pass is a setting you name.** Function discovery depends on the pass (`aa`, `aaa`; `r2 -h` and `aa?` list them). Record `r2 -v`, the pass and the command, and keep the output: `r2 -N -q -c 'aaa; afl' SAMPLE > "$OUT/functions.txt" 2> "$OUT/functions.err"` (disassembly can contain credentials: use a job with `secret_output: true`, read addresses and lengths, cite those). "No function there" and "no reference to this address" (`axt <addr>`) are bounded by that pass.
3. **Indirect calls, computed jumps and imports resolved at run time are gaps.** Count the ones you could not resolve and say so; a missing cross-reference does not show the code is unused, and a function that exists is not shown to be reachable from the entry point.
4. **Most of a binary is not the author's code.** Compiler runtime, static libraries and language runtimes dominate; without library signatures you cannot separate them, so say which functions you read and why those.
5. **A decompiler is a reconstruction.** This pack declares none. If the operator supplies one, treat its output as a lead and confirm each claim against the disassembly instructions you can cite.
6. **Evidence stays data.** Do not load a project, script, plugin or rc file the sample or its directory supplies (`r2 -N` loads no user settings or scripts; see `r2 -h`), and do not step or emulate the code in this leaf: derived results are not observations.
7. A capability claim cites a typed address, the instructions read and what stays unresolved; "can" is the strongest verb, and import names alone support a dependency observation only (`pe/structure`).

Only if the binary is Go or Rust, .NET, Python-packaged or packed, read `runtimes/go-rust`, `managed/clr`, `runtimes/python-packaged` or `packing/static-recovery`.

Sensitive output: disassembly and string references can hold credentials and keys; write them to `$OUT`, cite address and length, never the value, a fragment or a hash.

Shows: instructions and references at addresses, under a named analysis. Does not show: execution, reachability, intent, or that unresolved code is benign. Record: `r2` version, pass, architecture and bits, entry point with its type, the files, the unresolved indirect calls.
