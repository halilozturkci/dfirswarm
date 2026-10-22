---
id: triage/what-you-have
title: Classify a memory capture first
when: A memory image, crash dump, saved VM state, paging or hibernation file is in the evidence.
needs: [evidence/verify]
tools: [mem_profile, check_inputs]
requires_host: []
---

Use when the evidence includes a memory image, a process dump, a crash dump, a VM's saved state, a paging file or a hibernation file. Not for choosing plugins (`triage/volatility`) or for a capture no framework reads (`triage/no-framework`).

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

Only if the file is a crash dump, a LiME file, `hiberfil.sys` or a `.vmem`: three
things change the whole examination (locators, a saved state, a `.vmem` that needs
its metadata). Read `triage/container-details` for how.

Before you report, check the input's integrity again. Every conversion is a
derivative with its source reference and conversion record.

**Does not show.** From the header alone: that the capture is complete or
consistent, which build or architecture it is, or when it was taken, unless the
format records that time and the acquisition record agrees.

Record: the input's hash, the format and the evidence for it, the architecture, the captured ranges, whether the capture completed.
Sensitive output: `mem_profile` prints header facts and two short strings read from the capture, a kernel release and a Windows build string, each only when it has the grammar of a version; cite offsets, never content.
