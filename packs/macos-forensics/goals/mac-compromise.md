# A Mac that was compromised

This machine is believed to have been compromised. Establish what happened on
it, in order, with a citation for every step.

Read the skill index with `skill()` before you start. `triage/system-profile` is
the first ten minutes, and most of what you will read is a binary property list
rather than text.

## Questions

1. The system profile: product version and build, recorded hostname, setup-related
   evidence and its limits, timestamp encodings and timezone assumptions, and the
   acquired containers, volumes and snapshots examined.
2. Initial access: how the operator first reached this machine, with the
   artefact that shows it and the time in UTC.
3. Persistence: acquired launch items, login and background registrations, scheduled
   tasks, profiles and extensions relevant to the suspected compromise; distinguish
   configuration, enabled state, execution and maliciousness, and bound any negative
   by the coverage you examined.
4. Privacy authorization: the states recorded in the acquired system and user TCC
   stores, their client and service identities and any applicable policy; give
   historical grant or use times only where further evidence supports them.
5. Activity: retained application, device-state and session evidence, separating
   account association, remote activity and any independently supported attribution
   to a person.
6. File system changes: retained FSEvents observations and their corroboration, with
   relative order or explicitly justified time bounds; say when event times cannot be
   established.
7. Snapshots: using a snapshot-capable parser, whether the container holds any,
   and what a previous state shows that the live one does not — or state that
   the available parser cannot answer the question.
8. The timeline in UTC, and what you could not establish.

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

`work/report.md` exists and answers questions 1 to 8 under the headings `## 1.`
through `## 8.`. Every claim cites a path with a hash, a plist key, a log
predicate, a knowledgeC stream, or the command that produced it. The ledger
holds one `answer` entry per question (`question:1` to `question:8`) and one
each for `summary` and `narrative`, with every defect the answers check names
fixed or named by a limitation, and the critic, who wrote none of them, has
recorded `attest` or `dispute` on each answer, saying what they verified.
`inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7 8; do grep -q "^## $n\." work/report.md || exit 1; done`
- `grep -qiE 'UTC' work/report.md`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 8`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4,5,6,7,8,summary,narrative`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`
