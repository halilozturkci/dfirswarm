---
id: triage/what-you-have
title: Verify and classify a memory capture before anything else
when: The evidence includes a memory image, a process dump, a crash dump, a VM's saved state, a paging file or a hibernation file.
needs: [evidence/verify]
tools: [mem_profile, check_inputs]
requires_host: []
---

Memory arrives in half a dozen containers and they are not interchangeable. Naming
the wrong one wastes an hour and produces a framework error that reads like a
corrupt image.

First fetch `evidence/verify`: compare the inputs with the manifest and the
acquisition record, and run `check_inputs`. Then run `mem_profile`.

    raw / .mem / .vmem          flat memory has no header: nothing in the file says so
    .vmem with .vmss or .vmsn   the guest's memory, and the saved-state metadata beside it
    Windows crash dump          a PAGEDU64 or PAGEDUMP header; its dump type says what the file holds
    hiberfil.sys                HIBR or WAKE, or a zeroed header: a saved state, compressed as a rule
    LiME / AVML                 Linux, with their own framing
    ELF core                    a hypervisor's guest-memory dump, or one process's core

`mem_profile` is a heuristic first pass over the header and a sample. Its
"unrecognised" is not a finding that the file is RAM (a flat capture and a file that
is not memory look alike), its operating-system and build hints are strings found
in sampled ranges, and `file_pages_4k_estimate` is the file's length over 4096, not
a count of captured pages. Confirm the format, the architecture, the captured ranges
and that the capture completed before framework analysis, from validated headers and
the acquisition record, not from the file name.

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

Before you report, check the input's integrity again. Every conversion is a
derivative with its source reference and conversion record.

**Does not show.** From the header alone: that the capture is complete or
consistent, which build or architecture it is, or when it was taken, unless the
format records that time and the acquisition record agrees.
