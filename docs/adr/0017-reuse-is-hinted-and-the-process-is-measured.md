# Reuse is hinted, and the process is measured from its registers

A job is never merged with another seat's behind the agent's back, and it is
never silently repeated either: when another seat already ran the same tool or
the same command over the same objects, the answer names that job, its lead
and what it made, and an output that is byte for byte an earlier job's says
so. A second run meant as a check says so too. Only a typed recipe over the
same object is answered with the earlier job. How a run worked is measured
from its own registers, metric by named metric, with each definition written
down, and two runs of one goal can be set side by side, question by question.

Amended 2026-11-13: one tool call is now joined to the job that already
runs it, the identical whole-object call; see "Amendment: an identical
whole-object tool call is joined" at the end. A command is still never
merged.

Status: accepted, 2026-09-28; amended 2026-11-13. Designed by Claude, Fable and Astra (Plan 3,
joint-final A5 and round 3's Phase 5) and approved by the owner with the rest
of Plan 3. It is Phase 5's reuse and metrics part; the calibration cases are
their own (`calibration/`, `scripts/calibrate.ts`).

## Context

- Merging raw jobs was measured before it was done (2026-09-27): a command
  or a tool job got a shadow key, the sha256 of its whole spec (the command
  byte for byte, its timeout, its profile, its arguments) over its declared
  objects by digest, and a second job with the same key was written to the
  journal as `job_would_merge`. Both ran. On the three runs of the last CTF
  round the key matched none of 393, 127 and 190 keyed jobs. Agents did
  repeat each other's work, but never byte for byte: another timeout, another
  flag, a `| head` at the end. The duplication is at the level of object ×
  operation, which a whole-spec key cannot see.
- A merge at that level would be wrong: two jobs running `strings` over one
  disk image with other flags are not one job, and an agent that meant to
  check a peer's result would be handed the peer's result. What the agent
  lacked was the knowledge that the work was there.
- Typed recipes were merged already (`job_deduplicated`: the same recipe, its
  sha256 and image, over the same object by content), and that merge is
  sound: a recipe's identity is its own.
- The runs had no process measures of their own. ctf12's figures (quick and
  unreviewed negatives, refused `done` calls, woken seats' claims, the tail
  after every question was answered) were counted by hand from the registers,
  and Astra found earlier metrics that named one thing and counted another:
  a lead held at its open against ownership retained, a dependency satisfied
  against one withdrawn, how long a lead was blocked against how long a wake
  took, a question's first answer against its first supported one.
- Two runs of one goal agreeing was read as confirmation; two runs of one
  harness can share a blind spot.

## Decision

1. **The shadow key is retired.** No command or tool job gets one, and
   nothing writes `job_would_merge`. A journal that has them still reads:
   they are ignored by the job service and counted apart by the metrics.
2. **A job's reuse identity** (`scripts/job-reuse.ts`) is kept on its
   `job_accepted` line as `reuse: {op, objects}`, for a command or a tool
   with a declared scope: `op` is `tool:<name>`, or `command:<word>`, the
   leading command word (`protocol.ts leadingCommand`, the one the forge
   hints use); `objects` is the declared scope as resolved, each file by its
   sha256 and each directory of the evidence, the store or the catalogue by
   its path. An agent's own file is live and not known by its digest until
   the job starts, and a job over everything has no objects: neither is
   compared. Digests, paths and command words only; no format, no output.
3. **`similar` at `job_run`.** At acceptance, the other seats' jobs under
   way or committed, with the same tool or the same leading command word,
   that read at least one of the same objects, are named in the answer with
   their seat, lead, state, status and outputs, whether the objects are the
   same or overlap, and how close the operation is (the same command, or the
   same tool with the same arguments, ranks first). The whole list is a
   `job_similar` line; the answer carries eight and names the line for the
   rest. The job runs as asked; the agent may cancel it. The hint is sought
   after the job is registered and queued, and never holds it up: a line
   that cannot be written leaves every similar job in the answer.
4. **`same_as` at commit.** A committed job's non-empty file whose sha256 is
   an earlier job's output names that job and file, on a `job_same_as` line,
   the job's record and its view. The file is the job's own either way. The
   index of earlier outputs is built from the manifests in the background,
   off the store's one-at-a-time commit path; a commit only looks it up in
   memory, and one made while it is still being built is answered once it
   is. The console's Jobs tab shows both hints for a job, every entry.
5. **`independent: true`** on `job_run` (a command or a tool) records an
   intended reproduction on the spec. `similar` is still shown; the metrics
   count reproductions apart from duplicates.
6. **Merging stays for typed recipes only**, as it was.
7. **Metrics** (`scripts/metrics.ts`, `swarm.sh metrics <run> [--json]`)
   read the registers only (leads, the finish register where it exists,
   questions, the ledger with attestations and disputes, requests, the store
   journal, the network, the trace, the seats' token records) and write
   nothing. Each figure is a count of named records, the JSON names them by
   id and code, and no free text a record carries is copied (no answer
   value, finding or command, no dispute's why, no done's or stop's reason).
   The answer metrics are over the questions in scope at the run's end (not
   withdrawn, not a follow-up after done); older answers are history. A
   negative is what the finish gate holds as one, a premise rejected on a
   search alone included, and coverage whose results no longer stand is
   stale, never complete. The set: quick
   negatives; unreviewed negatives, material and background; coverage
   completeness; offers by outcome (accepted, declined, taken by another
   seat, lapsed), with wakes from before offers apart; `done` calls, refusals
   and deferrals; the tail to the end from readiness, from the first answers
   and from the final ones, each its own figure; acquisition requests and
   gaps; interpretations valid or on a superseded or disputed entry;
   reversals, by new evidence or discoverable in the original; tokens per
   question, apportioned by the leads held; duplicates and reproductions;
   network requests, grants, refusals and captures. The definitions are in
   `docs/usage.md`, and each keeps apart what Astra found mixed: an accepted
   offer is not a woken seat's claim, readiness is not a first answer, a
   first answer is not the one that stood, an interpretation is valid only
   while its entry stands. The dependency and blocking figures are not in
   this set; a metric of either must keep satisfied from withdrawn and
   blocked time from a wake's latency.
8. **A register a run does not have is absent, never zero.** Each metric
   whose register is missing says "not recorded", in the table and as
   `recorded: false`; a run from before offers, the finish register or the
   reuse hints says so and is measured on what it has.
9. **`--compare <run-A> <run-B>`** sets two runs of one goal side by side by
   question section, each over its own scope: each standing result and its
   kind, whether a negative was reviewed, its coverage, an acceptance while
   it stands. A result class that was never recorded is not guessed at. It
   flags a negative the other run asserts (established or partial), and a
   negative both reached without complete coverage that still stands, as a
   possible shared blind spot, and says that agreement is not confirmation.

## Consequences

- Duplicate work becomes visible at the moment it would start, with the
  earlier job's outputs to read, and the choice stays the agent's. What was
  done twice, and what was meant to be, can be counted afterwards.
- Nothing about a job's own record changes: its outputs are sealed and cited
  as before, and a hint is never a merge. A heavier job over the same image
  by another seat is still run; the hint costs one scope resolution at
  acceptance and a manifest index built once per hub.
- A command whose leading word is a generic one (`python3`, `bash`) is
  similar to other such commands over the same objects; the ranking puts the
  same command first, and the answer carries eight of the list.
- The metrics make the gates of the next CTF round countable from the
  registers, not by hand, and a run without ground truth has a process
  measure. They measure the process, never the case: a figure is a count of
  records, and reading what a record means is the examiner's.
- Cost per question is an apportionment: a seat holding two leads has each
  call split between them. The reversal cause is a heuristic: evidence that
  arrived between two answers is not proof it caused the change.
- Not decided here: the calibration fixtures and their scorer (already
  built), the dependency and blocking metrics, and any merge of raw jobs;
  a merge would need the operation's semantics, which the harness does not
  know.

## Addendum: measuring a rule change (2026-09-29)

The finish rules changed four times in a day (the partial disposition, the
downgrade rule, the case premise, the uncited lead findings), and each was
measured by hand: "over s993d40's registers it names two entries". The run
s9722fa showed what a rule that is not measured against a recorded history
costs: readiness and the answers check read a partial answer two ways, the
seats read the disagreement as a refusal, and the case lost every positive
answer. Claude, Fable and Astra agreed (Plan 3's known limits, the joint
position of 2026-09-29) that replay comes first: a recorded history read
again under a given harness's rules, with no model call, before a change
is trusted or a paid run is spent on it.

- **Replay** (`scripts/replay.ts`, `swarm.sh replay <run>`) copies a run
  and evaluates a checkout's answers check, finish gate, verdict, readiness,
  finish register, report standing and custody seals over the copy, each
  checkout in a process of its own, and prints the projection values-free
  (codes, ids, counts, the harness's own words; `--show-text` adds the lines
  that quote records). `--compare` sets two checkouts side by side and names
  each difference; the run's own harness is the hub's frozen copy, or the
  commit its registry records, extracted with `git archive`. The run is
  never written: its registers are hashed before and after. The goal's own
  commands are not run; they do not change with the harness.
- **Contract fixtures** (`tests/fixtures/contract/`) are synthetic
  histories made through the harness's own acts, one per rule the finish
  rests on: a partial disposed under every stop policy, an established
  claim held a best candidate, a negative nobody reviewed, evidence gone
  stale and cleared, sweep hits named and examined, a post late against the
  report, an objection racing the finish, a resumed run sealed twice, a run
  with warnings and nothing else, and the c10 partial cascade (s9722fa,
  reconstructed). Each `expect.json` is written from these ADRs, never from
  the code's output, and names the decisions it is written from. Under
  every fixture and every stop policy it names: readiness, the answers
  check and the finish gate agree on each question's disposition; a warning
  never holds; every custody verdict verifies as a prefix. A later item adds
  its own cases. The Fable review of the limits branch found the agreement
  blind to a question the gate reads accepted while the answers check still
  holds a defect on it (the check's verdict refuses the done): replay now
  counts that question held through the check, and two fixtures hold it
  (`accepted-excused`, a premise pair and an unreviewed answer, all
  accepted, disposed and ready; `accepted-negative-held`, an accepted
  negative whose coverage went stale after it, held by all three).
- **The acceptance** is the c10 cascade replayed under both rules: under
  3338e3c (the harness s9722fa ran with) readiness holds the six partial
  answers as best candidates while the answers check and the gate dispose
  them partial; under the rule since, all six are disposed and readiness is
  ready. The test extracts 3338e3c from the repository's history and runs
  it, rather than asserting what it would say; a checkout without that
  history skips the half and keeps the expectation on record.
- **What replay cannot measure.** It measures the decisions the rules make
  on a history the agents already wrote. A rule that changes what the
  agents do (a hold that sends a seat to run a broad parse, a warning that
  makes an answer be recorded again) shows only as where it would fire;
  whether it helps is measured by paired, repeated calibration runs with
  the versions, the team, the scorer and the budget frozen (Astra's H1),
  and a single run proves nothing.

## Amendment: an identical whole-object tool call is joined (2026-11-13)

"A tool is never merged" is no longer true for one case. The rest of this
record stands: a command is never merged, the hints are given as before, and
the choice to run a reproduction stays the agent's.

- **What was seen.** On the run s17fdfe-E1 six seats asked for the same
  whole-image extraction (the same tool, the same arguments, the same image
  by digest) within 188 seconds. Each got its `job_similar` hint, and every
  one ran: 655,871 files and 117.9 GB were sealed for 27 GB of distinct
  bytes, the seals of those trees held the store for most of the run, and a
  second walk of the same image put 17.7 MB on one `job_same_as` line. The
  hint arrives with the answer to `job_run`, after the job is queued; a seat
  that has already asked does not cancel a job over a hint.
- **Why this is not the merge the Context refused.** That merge was by
  operation over object, where the harness would have to know what two
  different commands mean. This one needs no semantics: the calls are the
  same in every part the harness can compare, and a tool, unlike a command,
  is a script fixed by its manifest's sha256 with typed arguments. The
  shadow key of 2026-09-27 matched nothing because it keyed commands byte
  for byte and included the timeout; tool calls over a declared image repeat
  exactly, and the timeout is not part of what is compared.
- **What is joined** (`scripts/job-service.ts` `sameWholeCall`): a `tool`
  job whose tool, arguments and declared objects (`reuse.objects`: files by
  digest, the run's directories by path) are the same as those of a job that
  is queued, running, being sealed or committed `ok`, when neither call
  names `members` (a call that picks members is its seat's own selection),
  neither has network or grants (two such runs may differ by themselves),
  and both run the same way (profile, supplied programs, secret output). A
  job that declared no objects is never the same as another. The committed
  job is preferred, else the oldest under way; one asked to cancel is never
  joined, and neither is a failed one.
- **What the asker gets.** The earlier job, with `joined` in the `job_run`
  answer saying whose it is, where it stands and how to cite it, and a post
  when it is done, as its requester gets. The line is `job_deduplicated`
  with `kind: "tool"`; the metrics count it apart from a merged recipe
  (`tool_joined`). The join is looked for before the seat's queue limit is
  counted: a joined call adds no job.
- **The way out is unchanged**: `independent: true` runs the call again as
  an intended reproduction, named and counted as before. Nothing is joined
  behind an agent that said so.
- **What goes with it.** A `job_same_as` line carries a count, the bytes and
  a few entries, and a long list is a side file beside the job
  (`store/jobs/<id>/same_as.jsonl`, named on the line with its sha256); the
  `derived_offered` line is bounded the same way
  (`store/jobs/<id>/derived_offered.json`). The Consequences' "a heavier job
  over the same image by another seat is still run" now holds for a command,
  for a tool call that differs in any compared part, and for an independent
  reproduction.
