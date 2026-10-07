# A ransomware incident

Establish what happened. Scope, possible exfiltration, entry and spread, the
encryptor and recovery impairment can be worked in parallel, in the order set by
ongoing harm and by how fast the evidence goes; the questions below are not a
sequence.

Read the skill index with `skill()` first. `scope/first-hour` sets the initial
preservation and scoping method; pursue the questions below according to
evidence volatility and incident impact.

## Questions

1. Scope: identify the affected assets and services, distinguish confirmed
   effects from candidates, and state the population examined and the timing
   uncertainty.
2. Exfiltration: establish what the evidence supports about access, staging,
   transfer, content, route, volume and timing; state an established, partial,
   bounded-negative or not-determinable conclusion with its coverage and
   detection limits.
3. Entry and dwell: how the adversary first got in, if the evidence shows it, and
   the earliest artefact you can tie to that activity. The earliest observed
   artefact is not the start, and encryption need not be the last event.
4. Spread: how the encryptor reached each machine and from which one, as far as
   the evidence shows.
5. Recovery impairment: shadow copies, backups, catalogues, boot recovery and
   stopped services: what was altered, attempted, reported successful and
   independently verified lost, as distinct from what was encrypted.
6. Identification: state the supported family or variant classification, the
   conflicting evidence and the attribution limits; an affiliate may remain
   undetermined.
7. Recovery: distinguish plausible routes, tested recovery results and
   operationally validated restoration, naming the unavailable evidence and what
   could change the assessment.
8. Whether the adversary may still have access, as a position with reasons.
9. The timeline in UTC, and what evidence was lost to the response itself.

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

`work/report.md` exists and answers questions 1 to 9 under the headings `## 1.`
through `## 9.`. Answer 2 gives its conclusion on a line of its own, in the form
`Exfiltration conclusion: <outcome>`, the outcome one of established, partial,
bounded negative or not determinable, and states the coverage and the detection
limits it rests on. Answer 8 is a position, not a shrug. No credential, key,
wallet address, victim identifier or hash of a secret appears in the report: it
cites where each is (the note id and offset, and the sealed job output that holds
it), and quotes a value only where a question asks for that value by name. The
ledger holds one `answer` entry per question (`question:1` to `question:9`) and
one each for `summary` and `narrative`, with every defect the answers check
names fixed or named by a limitation, and the critic, who wrote none of them,
has recorded `attest` or `dispute` on each answer, saying what they verified.
`inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7 8 9; do grep -q "^## $n\." work/report.md || exit 1; done`
- `grep -qiE 'UTC' work/report.md`
- `awk '/^## 2\./,/^## 3\./' work/report.md | grep -qiE 'exfiltration conclusion:[*_ ]*(established|partial|bounded[ -]negative|not[ -]determinable)'`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 8`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4,5,6,7,8,9,summary,narrative`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`
