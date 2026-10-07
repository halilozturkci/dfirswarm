# What runs on this machine that should not

A focused sweep rather than a full investigation: establish everything that is
arranged to run on this host, and which of it does not belong.

Read the skill index with `skill()` first. `persistence/mechanisms` is the map;
`packages/integrity` compares packaged files with a package database and says what
that baseline is and what it covers.

## Questions

1. Every scheduled job, unit and timer you can find on the machine, with the file
   it is in and that file's modification time, and what the inventory did not
   look in.
2. Which of them were added or changed outside the build window, and what that
   window is.
3. Every persistence route outside cron and systemd: profile scripts, preloads,
   modules, PAM, SUID binaries, authorized_keys with a forced command.
4. Which packaged files differ from the package database's recorded hashes.
5. For anything you flag: what it runs, as which user, and what it would have
   been able to reach.
6. What you could not establish, and what evidence would settle it.

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
through `## 6.`, every answer citing a file path with its modification time or
a command. The ledger holds one `answer` entry per question (`question:1` to
`question:6`) and one each for `summary` and `narrative`, with every defect the
answers check names fixed or named by a limitation, and the critic, who wrote
none of them, has recorded `attest` or `dispute` on each answer, saying what
they verified. `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 4`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4,5,6,summary,narrative`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`
