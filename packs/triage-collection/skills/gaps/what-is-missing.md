---
id: gaps/what-is-missing
title: What this delivery can and cannot establish
when: You write up or rely on anything drawn from a delivery.
needs: [identify/collector]
tools: [collection_id]
requires_host: []
---

Use when you bound an answer by what was delivered. Not for a disk image (`evidence/imaging`).

1. **Classify each object before you state limits**: copied file, parsed report, memory capture, logical container, volume image or physical-media image. A delivery may hold several. `collection_id` sorts objects by first bytes and name (`delivery.kind`, `objects`, `not_observed`); it does not say what was acquired or how much of the media. Neither an image extension nor an archive wrapper tells you which regions of the original media were taken. Route an actual disk or volume image to the base `evidence/imaging` and the `disk-volumes` recipe.
2. **Selected files do not carry the source volume's unallocated clusters or cluster slack** unless someone acquired them. Look for embedded images, raw region exports and specialised acquisitions before you write them down as absent. The delivered files can still hold deleted records, resident data, database free pages and record slack: examine or carve them, with offsets inside the artefact as locators (disk-sector offsets need an image). Surviving file-reference or inode metadata is evidence in itself; it does not bring back volume content you were not given. Never report "nothing hidden in slack" when volume slack was not delivered.
3. **List secondary sources one by one**: snapshot-derived files, complete snapshot or volume data, RAM captures, process dumps, pagefile and hibernation files, nested containers. None implies another. For each give a state: delivered and usable, delivered but partial or unreadable, not delivered, or unknown, with the effective profile, the actual outcome and the retained time range. A missing direct source limits what you can establish; read the supplied secondary traces before you call a question unanswerable.
4. **State the limit as the delivery's, not the case's.** "No unallocated space was delivered" is a fact about what you hold. It is not a finding that nothing was deleted.

Only if you write a negative or a completeness claim for one question: `gaps/coverage-statement`.

Shows: what kinds of evidence the delivery holds and which of the examiner's routes they open. Does not show: what the source machine held, or that an absent kind of object never existed.
Record: the object classes with their basis, each secondary source's state, and the questions each missing source limits.
