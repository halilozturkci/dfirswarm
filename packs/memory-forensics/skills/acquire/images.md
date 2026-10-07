---
id: acquire/images
title: Memory acquisition methods and their limits
when: The operator is deciding how to capture memory, or you must judge how a capture was made, what it covers and whether it can be trusted.
needs: [triage/what-you-have]
tools: []
requires_host: [avml]
---

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

**Order and cost.** The authorised examiner decides what is taken first, and records
the order and its trade-offs: volatile evidence early where safety, service
continuity, authority and the risk of changing or losing evidence allow. Record the
order actually used and the interval between RAM, paging files, hibernation data and
disk. A disk image taken before
memory, or hours after it, answers a different question, and the report says so.

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

**AVML.** The pack declares AVML at a pinned version and checksum so the operator
has the exact binary to take to the source host (`requires/host.json`). `avml` run in
an analysis VM captures that VM, not the subject, so it is not a collection route
from here. Before use, keep the binary's version and its own help (`avml --help`),
and confirm there the source it supports, the output formats, the unit of its size
limit and what it does when a limit or a read error is reached; do not copy a
command line from a document, this one included, until those are confirmed. Never
send an acquisition to a network destination the approved collection plan does not
name.

**What to preserve.** The acquisition log and its completion status; unreadable
ranges; the source system's identity, architecture and kernel build; the collector's
hash and version; start and end times with their zone and a comparison to a
reference clock; the output's size and hash. A conversion between formats is a
separate derivative: keep the original, and record the conversion command and the
hash of both.

**Does not show.** That a capture is complete, consistent or free of the collector's
own footprint because of its method's name; that two captures taken apart in time
describe one moment.
