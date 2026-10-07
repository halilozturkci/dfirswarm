# A Linux server that was compromised

This host is believed to have been compromised. Establish what happened on it,
in order, with a citation for every step.

Read the skill index with `skill()` before you start. `triage/system-profile` is
the first ten minutes and everything later depends on the timezone it
establishes.

## Questions

1. The system profile: distribution, kernel, hostname, install date, the
   timezone you converted every timestamp from, and the boot history.
2. Initial access: how the operator first reached this host, with the artefact
   that shows it and the time in UTC.
3. Accounts and keys: any account added, any UID 0 that is not root, any sudoers
   entry, and any key present in an authorized_keys file, with what the evidence does
   and does not say about when each appeared.
4. Execution: what was run, from the shell histories, sudo lines, the journal and
   any audit records the host retained, with at least two sources agreeing where you
   can get them, and which of these the host was configured to write.
5. Persistence: every scheduled job, unit, timer, profile script or preload that
   was added or changed, or the evidence that nothing was.
6. Integrity: which packaged files differ from the package database's recorded
   hashes (and what baseline that is), and whether the package database itself was
   touched.
7. Containers, if the host ran any: what was inside, what the writable layer
   holds, and whether any container could reach the host.
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
through `## 8.`. Every claim cites a path with an inode or a hash, a log line
with its file and time, a unit file, or the command that produced it. The
ledger holds one `answer` entry per question (`question:1` to `question:8`) and
one each for `summary` and `narrative`, with every defect the answers check
names fixed or named by a limitation, and the critic, who wrote none of them,
has recorded `attest` or `dispute` on each answer, saying what they verified.
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
