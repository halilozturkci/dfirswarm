---
id: triage/address-spaces
title: Which address space a number is in
when: A number from memory needs a place, or a raw region is compared with a rebuilt executable.
needs: []
tools: [mem_profile, mem_fs, mem_carve]
requires_host: [vol]
---

Use when an offset, a hit or a region must be placed in one address space, or a raw region is compared with an executable rebuilt from it. Not for the first classification of a capture (`triage/what-you-have`) or for the container formats (`triage/container-details`).

Three numbers look alike and are not the same:

- **Container offset**: a position in the file you hold. A byte search, a string hit or `mem_carve` gives this one.
- **Guest physical address**: a position in the machine's RAM. The file offset leads to it only through the container's own map: a crash dump's runs (`mem_profile` prints `physical_start` and `file_offset` for each), a LiME range header, a `.vmem`'s saved-state metadata. A flat image is the one case where the two may be equal, and then the acquisition record has to say it is flat.
- **Process virtual address**: meaningful only with its process (id, creation time, object address) and the page tables used to translate it, which need the kernel's symbols. The same virtual address in two processes is two places.

**Decision rules.**
1. Name the space of every number you write down. A hit is a container offset until a stated map turns it into something else.
2. Translate only with a map you can name: the run table, Volatility's layer stack with the plugin that used it (`windows.memmap` for a process's pages; verify the options with `vol windows.memmap --help`, since options change between versions), or the virtual path and MemProcFS version of a `mem_fs` listing. A translation you cannot reproduce stays a candidate.
3. A page that is not present, was paged out, or was never captured has no bytes. A region read from such an interval is missing those pages or has them padded with zeros by the tool; count them, and do not call the result the process's memory.
4. A **raw region** is the pages as the capture held them. A **reconstructed executable** is headers and sections laid out again by a tool, so section alignment, imports and relocations differ from the file on disk by that tool's choice. Compare each with its own kind, keep both when you rely on either (`processes/preserve-regions`), and do not read the difference as tampering.

**Shows.** Which space each number lives in, by what map it was translated, and which pages were unavailable.

**Does not show.** That equal numbers in two spaces name the same place; that a virtual interval is complete; that a rebuilt executable equals the file on disk.

Record: the space of each number; the map (run table, layer and plugin with its version, or `mem_fs` path and MemProcFS version); the process identity; the unavailable or zero-filled ranges.
Sensitive output: offsets and interval tables only. A region saved with `mem_fs` export or a plugin's dump option runs as a job with `secret_output: true` (`processes/preserve-regions`).
