---
id: verify/manifests
title: The collector's own record, and how to check it
when: Taking custody of a collection.
needs: [identify/collector]
tools: [collection_index, check_inputs]
requires_host: []
---

A collection arrives with its own claims about itself, and checking them is the
custody work that an image gets from its acquisition record.

**Hash what you were given, before you open it.** The container as delivered,
and then every file inside it. `check_inputs` does this against the run's own
`inputs.json`; `collection_index` produces the per-file list that goes in the
package.

**Compare against the collector's manifest.** KAPE's copy log carries a hash per
file; Velociraptor's `uploads.json` carries size and a hash; UAC writes a
bodyfile with sizes and times. Where a hash differs, say so and say when the
difference appeared: between collection and delivery is a custody question,
and it is a serious one.

**Read the skip log, and put it in the report.** Preserve the collector's reason
for each failure. Do not turn a lock, permission error, missing path, unsupported
object, or collector defect into a claim about user activity without separate
evidence.

**Record who collected it.** The account the collector ran as, the machine, the
start and end times, and the version of the tool. That is the equivalent of the
imager's own record, and a reviewer will ask for it.

**Check the times the collector recorded against the files' own.** A collection
whose files all carry the collection date rather than their original timestamps
was made by a tool, or a copy step, that did not preserve them — and every
timestamp-based conclusion in the case is then about the copy rather than the
machine. This is a real and common failure, usually caused by an intermediate
copy over a protocol that drops metadata, and finding it late invalidates a lot
of work.

Then treat `inputs/` exactly as you would an image: read-only, hashed before and
after, and nothing written into it.
