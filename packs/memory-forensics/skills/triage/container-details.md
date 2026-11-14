---
id: triage/container-details
title: Locators, saved states and VMware memory
when: A crash dump, LiME file, hiberfil.sys or .vmem, or an offset to translate.
needs: []
card: mem_profile {"path": "<dump>"} names a container only from its header. A crash dump's physical address is not a file offset: use the runs it prints (physical_start, file_offset) and keep both locators. A LiME file is ranges behind 32-byte headers. hiberfil.sys is a saved state, not the state at acquisition, and usually needs a decoder, which mem_profile is not. A .vmem needs its .vmss or .vmsn for physical mapping and process attribution; a literal search works without. Does not show: that hiberfil.sys predates anything, or that a .vmem alone supports attribution.
tools: [mem_profile]
requires_host: []
---

Use only if the capture is a Windows crash dump, a LiME file, `hiberfil.sys` or a `.vmem`, or you must translate between kinds of address. Not for the first classification (`triage/what-you-have`).

Three things change the whole examination:

1. **Locators.** A container file offset, a guest physical address and a process
   virtual address are different things. A full Windows crash dump lists physical
   runs and stores them one after another after its header, so a physical address
   is not a file offset: `mem_profile` prints `physical_start` and `file_offset` per
   run and checks the runs for order, overlap and the size of the file. Other dump
   types map memory differently and may leave out large classes of it. A LiME file
   is its ranges one after another, each behind a 32-byte header. Record the
   translation method and keep both locators.
2. **`hiberfil.sys` is a saved state, not the state at acquisition.** Establish its
   time and what it holds from the file and the acquisition record; do not assume it
   predates anything, or holds a whole user session. It usually needs a decoder
   before its memory can be searched, which `mem_profile` is not.
3. **A `.vmem` needs its metadata to be mapped.** Keep it with its `.vmss` or `.vmsn`
   and say which snapshot they belong to. In Volatility 3 2.28.2 (as of October
   2026) the VMware layer reads that metadata to map the guest's memory regions, not
   only CPU state. Without it, literal searches of the `.vmem` still work; physical
   mapping, process attribution and rebuilding across pages stay limited until
   validated.

**Does not show.** That a physical address is a file offset; that `hiberfil.sys` predates anything or holds a whole user session; that a `.vmem` without its metadata supports physical mapping or process attribution.

Record: the translation method with both locators, the saved state's time and how it was established, the `.vmem` with its `.vmss` or `.vmsn` and the snapshot they belong to.
Sensitive output: offsets and run tables only; no memory content in a post.
