# Taking custody of a triage collection

Before any examination: establish what this delivery is, what it can and cannot
establish, and whether it is what it claims to be.

Read the skill index with `skill()` first. `gaps/what-is-missing` says what the
report has to state once, plainly, early.

## Questions

1. Which collector produced this, how you know, and which profile or target set
   it used.
2. The collector's own record: who ran it, on what machine, as which account,
   when it started and finished, and the tool version.
3. What the collector's records say it skipped or failed to copy, in its own
   words, and what each limits in what can be asked.
4. What this delivery can and cannot establish, stated for a reader who is not
   an examiner: name unallocated space and say whether it was delivered.
5. The delivered-object inventory: identities, sizes, available digests,
   supported source mappings, unresolved mappings, omitted objects and
   enumeration failures.
6. Integrity and time provenance: agreement with the run baseline and supplied
   manifests, unresolved discrepancies, and the provenance and reliability of
   each timestamp layer.
7. What the case will need that is not here, and whether it can still be
   collected.

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
through `## 7.`. Answer 4 is written for a non-examiner. Answer 6 distinguishes
source-filesystem, embedded-record, archive-member and analysis-filesystem
timestamps, stating what is verified and what remains unknown. The ledger holds one `answer`
entry per question (`question:1` to `question:7`) and one each for `summary`
and `narrative`, with every defect the answers check names fixed or named by a
limitation, and the critic, who wrote none of them, has recorded `attest` or
`dispute` on each answer, saying what they verified. `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7; do grep -q "^## $n\." work/report.md || exit 1; done`
- `sed -n '/^## 4\./,/^## 5\./p' work/report.md | grep -qiE 'unallocated|logical acquisition'`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 3`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4,5,6,7,summary,narrative`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`
