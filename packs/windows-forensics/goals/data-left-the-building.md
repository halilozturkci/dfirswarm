# Did data leave this machine, and how

Somebody is believed to have taken data off this host. Establish whether they
did, by what route, and what it was.

Read the skill index with `skill()` first. `registry/devices` covers removable
media, `browser/artefacts` covers upload and webmail, `execution/srum` is the
one artefact that gives byte counters (and says what they do not show), and
`artifacts/shell` says what its records show about what was opened from where.

## Questions

1. Removable devices: every device attached, its serial, the first and last
   connection, the drive letter, and which user mounted it.
2. Files: what was opened, copied or staged, and from where — with the link
   files, jump lists, shell bags or journal records that show it.
3. Network routes: uploads, webmail, cloud sync clients or shares, with the
   artefact for each.
4. Volume: how much data a program moved, and over which network, where SRUM or
   another artefact can say.
5. Attribution: which account did each of the above, and what makes you confident
   it was a person at the keyboard rather than a token.
6. What was destroyed afterwards, if anything.
7. What you could not establish, and what evidence would settle it.

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
through `## 7.`, every answer citing an artefact a reviewer can re-open. A
device named in answer 1 is tied to something in answer 2 or the report says it
could not be. The ledger holds one `answer` entry per question (`question:1` to
`question:7`) and one each for `summary` and `narrative`, with every defect the
answers check names fixed or named by a limitation, and the critic, who wrote
none of them, has recorded `attest` or `dispute` on each answer, saying what
they verified. `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 5`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4,5,6,7,summary,narrative`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`
