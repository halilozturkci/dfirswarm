---
id: managed/decompiled
title: clr_inspect's labelled C# reconstruction
when: clr_inspect decompiled an assembly, or its file is to be read.
needs: [triage/quarantine]
tools: [clr_inspect]
requires_host: [ilspycmd]
---

Use when `clr_inspect` ran with `decompile`, or you must read its reconstruction file. Not for citing decompiled C# as the author's source, or for what the assembly did.

1. **Where it runs.** `decompile` is refused as JSON outside a job run with `secret_output: true`, before anything is read: the C# holds the assembly's string literals, names and resources. `ilspycmd` is optional; the metadata mode needs no program.
2. **Where it lands.** `reconstruction.reconstruction_file` under `$OUT/tool-output`, mode 0600, never printed inline; the program's error text is in `log.log_file`, also never printed. The file opens with three comment lines that call it a reconstruction by a decompiler, an interpretation of the IL and not the author's source, with the program's version line and the SHA-256 of the assembly. Its own SHA-256, line count and size are in `reconstruction`; `decompiler.version_output` is the version as printed.
3. **Read `status` for what it says.** `complete` means the program exited 0 and its output, within `max_output_bytes`, is the file named. It does not mean the C# is faithful, compiles or is the author's. A nonzero exit is `partial` (the tool takes it as the program reporting that parts could not be decompiled; the program's words are never parsed). The time limit or the output budget ends the program and removes the partial file, so nothing is kept. A file that changed while the program read it is `failed`.
4. **Unobserved, as the tool's manifest says.** `ilspycmd` was never run for real when the tool was written (no .NET runtime was available): the tests use stand-ins, and the options are those of the package's documentation (11.2.0.10050). Whether the program makes any request of its own, and what shared libraries the amd64 Native AOT build needs, were not measured; the tool starts it with the update check disabled.
5. **A known limit.** Before it reads the file the tool ends every process the program left behind (a child forked and left, one in a session of its own, a double fork: the tool adopts and kills them, holding the output or not); one found makes the answer `partial` (`process_left_behind`), never `complete`. What it cannot end is a process that is no descendant of the program (started through a service manager or a socket): where `/proc` is readable it is looked for (held open, still growing or given a second name by a hard link: `partial`, `process_left_running`, file removed); otherwise the file may still grow. Measured with stand-ins only. Hash the file again before you rely on its hash.
6. **Names and structure.** Names in a reconstruction can be obfuscated or generated. The IL and the metadata are the evidence (`managed/clr`): cite those; a string literal from it stays in the file; cite file, line and length, not the text.

Sensitive output: the reconstruction and its log can hold credentials; they stay under `$OUT`.

Shows: that the program produced a file and under what version. Does not show: the author's code, that the C# compiles or is complete, or what any method does. Record: `status`, `limits_hit`, `decompiler` (version, exit code), both SHA-256 values, the second hash.
