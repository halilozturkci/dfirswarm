# What on this evidence is encrypted, and what can be opened

A focused pass over an exhibit before the main examination, so that nobody
spends a day on something the metadata would have answered.

Read the skill index with `skill()` first. `identify/headers` is the order of
questions, and `keys/where-they-hide` is where key material the case supplies is
located and safeguarded.

## Questions

1. Every encrypted volume, file and archive you identified in the evidence, within
   the coverage you state, with the scheme each one uses and how you identified
   it. A signature survey does not prove the set is complete.
2. For each volume: the key protectors or key slots present, and whether the
   metadata alone says it can be opened without a secret.
3. For each archive or document: whether the file names are readable without the
   password, and what they are if so.
4. Key material already in the evidence: where it is, what it was found to open
   (if anything was tried, and by whom authorised), and how you found it, with the
   coverage of the search. Do not put values in the report.
5. What was opened, by which protector route (with the sealed reference of the material
   used, never the material), and the hash of the unlocked image.
6. What could not be opened, and exactly what would be needed to open it.

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

`work/report.md` exists and answers questions 1 to 6 under the headings `## 1.`
through `## 6.`. No key, password, recovery value, password fragment or hash of a
secret appears in the report or the ledger: record the authority, the source
locator, a non-secret identifier, the examination result and the sealed reference
of the sensitive output instead. The ledger holds one `answer` entry per
question (`question:1` to `question:6`) and one each for `summary` and
`narrative`, with every defect the answers check names fixed or named by a
limitation, and the critic, who wrote none of them, has recorded `attest` or
`dispute` on each answer, saying what they verified. `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6; do grep -q "^## $n\." work/report.md || exit 1; done`
- `! grep -qE '[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}' work/report.md`
  (this catches one recovery-password shape in the report and nothing else: it is
  not a check for hashes, fragments, other credentials or a command line that
  carries a secret, and the instruction above is what holds)
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 3`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4,5,6,summary,narrative`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`
