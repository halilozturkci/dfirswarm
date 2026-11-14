---
id: evidence/tool-validation
title: Validate a parser before trusting its result
when: A negative or decisive value rests on a tool's output, or the tool is new.
card: Exit 0 shows a tool ran, not that it read everything: read its status (a partial or failed output supports no absence) and record program, version and settings. A negative from ioc_scan needs a positive control, a planted sample in the same encoding. Two wrappers over one library are one reading. Does not show: that a tool is right because it succeeded.
needs: []
tools: [timeline_super, sqlite_snapshot, ioc_scan]
requires_host: [pinfo]
---

Use when a conclusion rests on what a parser or scanner printed. Not for the pack's own tool contracts (each tool reports its counts and bounds), or for interpreting an artefact.

A tool that exits 0 ran. That does not show it read everything, or read it right.

**Rules.**
1. **Name what ran.** The exact program and version, the image or build, and every setting that changes meaning (zone, parser filter, encoding, offset and sector size, what it skips). A format version it does not support is a limit of the examination.
2. **Read the status, not the exit code.** Parsed, empty, unsupported, failed, not attempted, and the first failures. `timeline_super` says `complete` when its pipeline finished; Plaso's own processing report (`pinfo`) says what each parser did. A partial or failed job's output can support a qualified observation and never an absence. `partial` with `program_group` means a program left a process running, or none could be ruled out: its files are not final.
3. **Check the decisive field against the bytes.** Locate the record by offset, read the raw bytes, and decode the field by the format's specification yourself, for the values an answer rests on.
4. **Independence is a property of the code, not of the count.** Two wrappers over one library, or two agents running one parser on one source, are one reading. A second parser written from the specification, or a measurement by a different method, is two only if it does not share the first's assumption or input copy: a shared misreading makes agreement prove nothing. `sqlite_snapshot` reads the WAL against the format and SQLite applies it; `counts_agree` says only that both found the same number of committed frames, not the same pages or rows.
5. **A negative needs a positive control.** Run the same search over a source or a planted sample where the answer is present, in the same encoding: a scanner such as `ioc_scan` that cannot find the known hit supports no absence. Build the sample from the format's specification or a known-good file, never from the parser's own output.
6. **Disagreement between tools is a result.** Do not keep the cleaner one: find the first row where they differ, decide from the bytes, and record both.
7. **Surprising output is a defect candidate.** A timestamp decades off, a field always empty, success on a file of another type: check the epoch, offset, format version and tool before concluding about the evidence.

**Record.** Tool, version and settings; the input's digest or reference; the status counts; the control you ran and its result; the independent check and what made it independent.

**Does not show.** That a tool is correct because it succeeded, or that an independent check was independent because it used another command.
