---
id: triage/coverage
title: What a memory search covered
when: Before writing "not in memory", or when a plugin or scan returned nothing, stopped early or counted.
needs: [evidence/coverage]
tools: [mem_carve, mem_profile]
requires_host: [vol]
---

Use when a memory answer rests on something not being found, or on a count. Not for the general readings of an empty result (`evidence/coverage`) or for choosing plugins (`triage/volatility-plugins`).

Memory adds two questions to the base rule: what the capture holds, and what the scan could reach. Name which of four you have:

- **unavailable**: nothing could be asked. The container is not decoded (a hibernation file), the metadata is missing (a `.vmem` without its `.vmss` or `.vmsn`), the kernel has no symbol table, the plugin does not exist in this version, or the pages were never captured.
- **failed**: an error, a timeout or a plugin that raised on a damaged structure. What it printed before is partial.
- **partial**: the run stopped at a limit: a clock, a size or a result cap, `mem_carve`'s `status: partial` with `coverage.resume_start` for the rest, or a plugin's own bound. Only the part it reached is read.
- **completed-negative**: the scan ran over stated ranges and finished with no match. Only this one supports "not found", and only for those ranges, patterns and encodings.

**Define the search before you run it.**
- *Formats and captured ranges*: which ranges the capture holds, from validated headers and the acquisition record. `mem_profile`'s `sampled_ranges` are the bytes it sampled, and `file_pages_4k_estimate` is the file's length over 4096, not a count of captured pages.
- *Framework initialisation*: `vol`'s layer stack built, the kernel identified, the symbols matched (`triage/volatility`). A framework that did not initialise examined nothing, whatever it printed.
- *Per-plugin coverage*: a list plugin walks one structure (a linked list, a table) and cannot show an object that is unlinked or freed; a scan plugin finds remnants as well. Say which one produced the empty result.
- *Scan limits*: the start and length, the clock, the result cap, the encodings searched (UTF-8 and UTF-16LE).
- *Unreadable mappings*: an object whose pages are not present is not readable here, which is different from absent.

**Shows.** Which of the four readings a memory result has, and over which ranges and patterns.

**Does not show.** That a list plugin's negative covers objects it does not walk; that a clean exit is a complete scan; that a count is every object the machine had.

Record: for each negative, its reading, the input's hash, the ranges, the tool or plugin with its version and options, the stop reason, and what was not run.
Sensitive output: none here; the search terms you record are not secrets, and a hit's content stays under `strings/discipline`.
