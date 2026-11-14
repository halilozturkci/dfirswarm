---
id: acquire/images
title: Memory acquisition methods and their limits
when: The operator is choosing how to capture memory, or you judge how a capture was made.
needs: []
tools: []
requires_host: []
---

Use when you must judge how a capture was made, what it covers and whether it can be trusted, or the operator is deciding how to capture. Not for classifying the file (`triage/what-you-have`).

Analysis usually starts after acquisition, but you will be asked to judge one, and
the method decides what the image can be trusted to show. Collection is work on the
source system under the operator's authority; nothing here runs it for you.

**A live capture can be a smear.** The machine may keep running while the tool
reads, so pages read late can reflect a later time than pages read early. Record the
capture interval, the method, whether execution was paused, and what the method
documents about consistency. A framework reporting a contradiction may be
describing the capture, a missing page, a parser error or tampering: decide which
the evidence supports, and say it.

**The collector is on the machine and in the image.** Acquisition changes the system.
Record the collector's executable and driver identities, their verified hashes and
version, the start and end times, the output location and the known side effects.
Compare suspicious processes, modules and allocations with that record. A familiar
collector name does not make something legitimate, and an acquisition-related
explanation has to be supported, not assumed.

**Recognise the method before you judge coverage.**

    hypervisor snapshot or suspend   verify memory was selected, which files belong together
                                     (the memory file and its state or snapshot metadata),
                                     whether the guest was paused, what the hypervisor guarantees
    AVML, LiME                       Linux; the format, the source, the completion status and any
                                     unreadable ranges come from the acquisition record
    a kernel driver on Windows       the collector's own driver and buffers are in the image
    a Windows crash dump             limited by its configured dump type and by completing; a
                                     forced (NMI) trigger does not establish completeness
    hiberfil.sys                     a saved state: its time and coverage are established apart

When the case involves a virtual machine, ask for existing snapshots and their
metadata before anyone chooses another collector, and do not treat one method as
better than the others in every respect: a snapshot needs no agent on the guest, and
what it holds and when still has to be established.

Only if the operator takes a capture with AVML, orders the sources (RAM, paging files, hibernation data, disk) or lists what to preserve: `acquire/avml-and-preserve`.

**Does not show.** That a capture is complete, consistent or free of the collector's
own footprint because of its method's name; that two captures taken apart in time
describe one moment.

Sensitive output: an acquisition holds everything the machine held; cite its hash and size, never its content.
