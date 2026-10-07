# What this phone shows

An extraction from a phone, and the questions a case asks of one.

Read the skill index with `skill()` first. `extractions/what-you-have` decides
what can be asked at all, and it comes before everything else.

## Questions

1. The extraction: what kind it is, what it therefore cannot contain, the
   device it came from, and whether it is encrypted.
2. The device profile: operating system version, identifiers, the accounts on
   it, and the applications installed with their install and update times and
   what the package records say about installer, initiator and origin (a field
   that is missing or not a store is not a finding by itself).
3. Communications: messages, calls and the contacts behind them, with the
   database each came from.
4. What was deleted and recovered: the fragment, the page and offset it came
   from, the source it was read in, and what is inference rather than a row.
5. Location: where the device recorded being, with the accuracy of each fix and
   the source that produced it.
6. Activity: what ran, when, and for how long.
7. The timeline in UTC, with the epoch you converted each source from.
8. What you could not establish, and what evidence would settle it.

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
through `## 8.`. The kind of extraction and its limits are stated in answer 1.
Every recovered fragment is labelled as recovered rather than as a row. The
ledger holds one `answer` entry per question (`question:1` to `question:8`) and
one each for `summary` and `narrative`, with every defect the answers check
names fixed or named by a limitation, and the critic, who wrote none of them,
has recorded `attest` or `dispute` on each answer, saying what they verified.
`inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7 8; do grep -q "^## $n\." work/report.md || exit 1; done`
- `awk '/^## 1\./{f=1;next} /^## 2\./{f=0} f' work/report.md | grep -qiE 'logical|full file system|physical|backup|app export'`
  (answer 1 states the kind of extraction: the grep reads that section only)
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 6`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4,5,6,7,8,summary,narrative`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`
