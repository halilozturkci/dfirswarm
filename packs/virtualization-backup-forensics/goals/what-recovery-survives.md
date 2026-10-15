# What recovery survives

A set of virtualization and backup evidence (VM configuration, disk descriptors,
hypervisor records, backup job and audit exports), and the question of what was
done to the recovery path and what can still be restored.

Read the skill index with `skill()` first. `router/start` says which note
answers which question, and `evidence/boundaries` comes before any examination:
read the evidence natively, never run the hypervisor or backup product against
it, and never use a credential it holds.

## Questions

1. The evidence itself: which planes it covers (guest, VM files, hypervisor,
   management server, backup server, repository), which products and versions
   it names, how and when each export was taken, and what was not supplied.
2. The protected objects: the VMs, disks and snapshots the files list, which
   disks a configuration leaves out of snapshots or backups, and which
   configuration or inventory files could not be read.
3. The disk and snapshot chains: which are whole in the set, which are broken
   or disagree about their parent, which extents are missing, and which markers
   (an unclean close, a leftover delta, a lock file) the files carry, each with
   what else would corroborate it.
4. What was done through the management plane: snapshot, deletion, power and
   configuration operations, by which account, from where, with which outcome
   and on which clock, as each source recorded them.
5. The backup system's three accounts: what the catalogue, the repository and
   the retention setting each say, and where they disagree.
6. For each object that may have lost recovery data: requested, reported,
   observed and verified, kept apart.
7. Which recovery points survive: per object, the newest usable copy, the five
   tests of `recovery/survivability` with evidence or "unverified", and the
   dependencies of each copy on the damaged plane.
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
through `## 8.`. Every disk chain is reported with its status and the identity
check of each edge. Answer 7 gives each protected object's position on a line of
its own, in the form `Recovery position: <state> - <object>`, the state one of
restorable and tested, present with chain whole and untested, present with chain
incomplete, absent in the listings examined, or unknown; and says, for each, which
of the five tests have evidence and which are unverified. No credential, key,
token or hash of a secret appears in the report: it cites where each sits (the
source, the line or element, and the sealed job output that holds it) and what it
grants, and no credential found in the evidence was used. Times are stated with
their clock and zone. The ledger holds one `answer` entry per question
(`question:1` to `question:8`) and one each for `summary` and `narrative`, with
every defect the answers check names fixed or named by a limitation, and the
critic, who wrote none of them, has recorded `attest` or `dispute` on each
answer, saying what they verified. `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7 8; do grep -q "^## $n\." work/report.md || exit 1; done`
- `grep -qiE 'UTC' work/report.md`
- `awk '/^## [0-9]+\./{s=/^## 7\./} s && tolower($0) ~ /recovery position:[*_ ]*(restorable and tested|present with chain whole and untested|present with chain incomplete|absent in the listings examined|unknown)/{f=1} END{exit !f}' work/report.md`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4,5,6,7,8,summary,narrative`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`
