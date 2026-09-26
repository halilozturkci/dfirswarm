---
id: acquire/images
title: Acquiring memory, and what the method costs you
when: The operator is deciding how to capture memory, or you must judge how a capture was made.
needs: [triage/what-you-have]
tools: []
requires_host: [avml]
---

Analysis usually starts after acquisition, but you will be asked to judge one,
and the method decides what the image can be trusted to show.

**Every capture is a smear.** The machine keeps running while the tool reads,
so pages at the end were written after pages at the start. Structures that
straddle that gap can be internally inconsistent, and a framework reporting a
contradiction may be describing the capture rather than the machine. Say how
long the capture took where the tool records it.

**The tool is on the machine and in the image.** A collector's own process,
driver and buffers are in the memory you are examining, and they look exactly
like injected code to an unwary sweep. Two published runs nearly reported an
imaging tool's driver as attacker software. Check names and timestamps against
the acquisition record before you name anything.

Order of volatility, when there is a choice: memory first, then the page file
and hibernation file, then the disk. A disk image taken first and memory taken
an hour later answers a different question, and the report should say so.

Methods worth recognising:

    a hypervisor snapshot        the cleanest: the guest is paused, so no smear
    AVML, LiME                   Linux, into a portable container
    a kernel driver on Windows   what most commercial collectors use
    a crash dump forced by NMI   complete, and it stops the machine
    hiberfil.sys                 no tool at all, but a past state

A hypervisor snapshot of a virtual machine is the best evidence you will get and
it needs no agent on the guest. When the case involves a virtual machine, ask
whether one exists before anyone runs a collector inside it.

For AVML 0.20, make the source and the storage ceiling explicit, then hash the
completed file and record the command, start/end time and collector hash:

    avml acquire --source /proc/kcore --compress --max-disk-usage 16384 memory.lime.compressed
    sha256sum memory.lime.compressed

Use `/dev/crash` instead when the source host exposes it. Never use `--url` or
`--sas-url` during an evidence acquisition unless the approved collection plan
names that endpoint; an analysis VM should have no such route. `avml convert`
can turn `raw`, `lime` and `lime_compressed` into one another, but a conversion
is a derivative: keep the original capture, hash both, and record the format
arguments.
