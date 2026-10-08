---
id: evidence/verify
title: Establish evidence identity, integrity and provenance
when: Before substantive examination, after an integrity concern, and before reporting.
needs: []
tools: [check_inputs, image_layout]
requires_host: [ewfinfo, ewfverify]
---

Establish what the evidence is and that it is intact before you rely on it, and
say what that does and does not show. A hash match means these bytes agree with
the named baseline. It does not show who made the evidence, that the acquisition
was complete, or that the contents are true. Missing provenance or a failed
check is a limitation: record it, and name the conclusions it bears on.

1. Read `inputs.json`. It carries every file under `inputs/` with its size and
   sha256, taken when the run copied or bound the evidence. It is the baseline
   for this run, not for the evidence's history.
2. Compare the acquisition record if the case shipped one: an imager's log or
   `.txt`/`.csv`, or the record inside an E01, which `image_layout` returns
   (through `ewfinfo`). Say which bytes every digest covers: one container
   segment, an ordered set of segments, the decoded media stream, a volume, an
   extracted file, a derived output. Record the algorithm, the byte count, who
   supplied the expected value and the result, and compare digests only over the
   same bytes. The imager hashed what it acquired; `check_inputs` hashes the
   container files you hold. Quote them separately.
3. An E01 is a container, not a scope. Whether it holds a disk, a volume or
   collected files is in its acquisition record (an L01 is a logical
   collection), not in the format name.
4. `ewfverify` re-reads an E01's decoded stream and compares it with the digest
   stored inside it. It reads only, and it is slow on a large image: run it as a
   job. It shows the container is internally consistent, not that it matches the
   source device or is the whole of it.
5. Run `check_inputs` before substantive work and again before you write the
   report, allowing time to read every input. Preserve its result and look into
   every modified, missing or added item. A timeout, an unreadable file, a
   malformed manifest, an entry with no digest or a file it did not reach
   (`not_checked`) is an incomplete verification, not a pass. Its result is the
   pack tool's receipt; the harness writes its own `inputs_check` event when the
   run completes.

Check that the manifest accounts for every file and segment supplied, with a size
and digest for each regular file and the recorded target for each link. Record
the acquisition scope, the imager and its version, the source device or system,
start and end times with their zone, read errors or substituted bytes, each
transfer, and the protection that was actually enforced (SWARM.md says how
`inputs/` is held). Keep the original acquisition logs. Do not repair or replace
an input, or its baseline, after a mismatch: preserve the discrepancy and ask
the operator for an authorised explanation or replacement.

Nothing you do may write under `inputs/`: a refused write is recorded as a
violation against your name. Work in `work/`. If the evidence was bound in place
rather than copied, `inputs/` is a view of the operator's own directory, with the
same rule and more care.

**Does not show.** Agreement with a baseline is not authenticity, and a clean
check does not show the baseline was right when it was made or that what was
imaged is everything that existed.
