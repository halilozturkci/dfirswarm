# What was running on this machine

A memory image, and the question of what was on it and what it was doing.

Read the skill index with `skill()` first. `triage/what-you-have` names the
container before anything is run against it, and `strings/discipline` is the
rule every claim here has to survive.

## Questions

1. The container: what format the image is in, its size, whether it is
   contiguous, and which moment it represents.
2. What was running: the process list with parents, paths and start times, or —
   where no framework was available — what you were able to establish without
   one, said plainly as that.
3. Anything injected or hollowed: the process, the region, its protection, and
   the job reference of the sealed dump.
4. Network state: recovered endpoints and listeners, their supported owner
   associations, the enumeration or scanning method, and whether allocation
   state (the live table or freed structures) can actually be determined from
   the output used, and what it shows where it can.
5. Credential exposure: what a process could have taken, with the artefact that
   shows it. Do not put recovered secrets in the report.
6. Structures carved out of the image that a disk parser could read, and what
   each one said.
7. The timeline in UTC, and what you could not establish.

## How to divide the work

**Report author and critic.** Two of you take these roles early with
`name(doing=…)`, and they are different agents. The report author writes the
answers from the ledger, not from memory: compact first, read `ledger`, then
one `record(kind=answer)` per question (`section=question:<n>`) and one each
for `summary` and `narrative`, citing `E-<seq>` for every claim and stating the
confidence and its reason, the contrary evidence, the limitations, what else
could explain it and what would change the answer. When the ledger cannot
answer, reopen the investigation and say so on the board. The critic re-derives
each finding an answer rests on from its sealed refs and records `attest` (what
was re-derived, what only read) or `dispute` (why), then does the same for
every answer. The critic writes no answer; the author attests nothing of their
own. The sign-off is these acts, not a post. Nothing else is assigned.

## Definition of done

`work/report.md` exists and answers questions 1 to 7 under the headings `## 1.`
through `## 7.`. Every memory claim names a process and a region, or an offset.
The ledger holds one `answer` entry per question (`question:1` to `question:7`)
and one each for `summary` and `narrative`, with every defect the answers check names,
fixed where the evidence allows it, or named by a limitation that says what could
not be established and why (the run may then end and the defect stays counted; a
limitation does not fix it), and the critic, who wrote none of them, has recorded
`attest` or `dispute` on each answer, saying what they verified. Evidence that is
not there is stated as a supported partial, bounded-negative or not-determinable
answer, not as a finding.
`inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7; do grep -q "^## $n\." work/report.md || exit 1; done`
- `grep -qiE '0x[0-9a-f]{4,}|offset' work/report.md`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4,5,6,7,summary,narrative`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`
