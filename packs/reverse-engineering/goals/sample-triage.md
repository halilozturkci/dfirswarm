# What is this file, and what can its code do

A sample recovered from a case, and the question of what it is. Static analysis
only: nothing here is executed, and the report must say so.

Read the skill index with `skill()` first. `triage/quarantine` sets the order
and the rules; every claim in this report is a claim about the file, not about
its behaviour on any machine.

## Questions

1. What the file is, from its bytes rather than its name, with its sha256 and
   whether the extension agrees.
2. Structure: sections or segments, their sizes and permissions, the entropy
   profile, and what the profile does and does not suggest about packing.
3. What it declares: imports, exports, linked libraries, and the version
   information or original file name where there is one.
4. What its code can do: capability hypotheses mapped from the code, each with
   the locator behind it and the limits of the analysis.
5. Strings that matter, including the obfuscated ones, each with the function
   that references it — or which analysis recovered no reference to it (a
   bounded negative: function discovery, indirect addressing and decoding limit
   it).
6. Indicators another examiner could search for: hashes, mutexes, domains,
   paths, and a rule if you wrote one, with what it was built from.
7. What you could not establish, and what would be needed to establish it.

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
through `## 7.`. The report states that the sample was not executed. Every
material capability inference cites inspected code or structured feature
evidence with its locator and limitations; an import alone supports only a
dependency observation. The ledger holds one `answer` entry per question
(`question:1` to `question:7`) and one each for `summary` and `narrative`, with
every defect the answers check names fixed or named by a limitation, and the
critic, who wrote none of them, has recorded `attest` or `dispute` on each
answer, saying what they verified. `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7; do grep -q "^## $n\." work/report.md || exit 1; done`
- `grep -qiE 'not executed|static analysis only|no dynamic analysis' work/report.md`
- `grep -qE '[0-9a-f]{64}' work/report.md`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 3`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4,5,6,7,summary,narrative`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`
