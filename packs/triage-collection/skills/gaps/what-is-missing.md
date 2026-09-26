---
id: gaps/what-is-missing
title: What a logical acquisition cannot contain
when: Writing up anything based on a collection.
needs: [identify/collector]
tools: [collection_id]
requires_host: []
---

These limits apply to a **logical collection**, not to an E01/raw disk image.
Run `collection_id` first; it identifies a disk image and directs it to the
disk recipe instead of applying this checklist. For a logical collection,
state this once, plainly, early in the report. A reviewer must not have to work
it out, and an examiner must not let a limit of the evidence read as a finding
about the case.

**There is no unallocated space.** No carving, no recovery of a file whose
record was reused, no deleted data outside what a structure carries internally.

**There is no file slack**, so nothing hidden there.

**There is no volume**, so no partition table, no inode, no `-o` offset, and no
volume serial from `fsstat`. Every command in the packs that takes an offset is
irrelevant; cite by path and hash instead.

**There are no shadow copies**, unless the collector was told to collect from
them — most can, and most profiles do not. That is one of the highest-yield
artefacts on a Windows machine, and its absence is worth naming.

**There is no memory**, unless it was captured separately.

**There is only what the profile named.** A question about an artefact family
outside the target list cannot be answered from this evidence, and no amount of
care changes that.

Three sentences that belong in a report based on a collection:

> The acquisition was logical: a KAPE collection using the *SANS Triage*
> target set, made on 14 February at 09:12 UTC. Unallocated space, file slack
> and deleted records outside `$MFT` were never in our hands, so no carving was
> possible. Four targets failed to copy and are listed in appendix B; all four
> were in use at the time.

That is not a disclaimer. It is the scope of the evidence, and it is what makes
everything else in the report defensible.
