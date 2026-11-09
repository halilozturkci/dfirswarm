# A negative is bounded, a cap pauses, and a run can be resumed

An answer says what it is: established, partial, a bounded negative, not
determinable, out of scope, or a premise not supported. A negative says what
was searched, over which objects, and whether the event would have left a
trace there; another seat reviews it before it is trusted, and it is worded as
what it is: "no evidence of X was found in <scope>", never "X did not happen"
unless the bar for that is met. A cap pauses the run for the operator instead
of ending it, and a run that ended can be continued, in the same sandbox, on
the same chains, with every earlier seal still valid as a prefix.

Status: accepted, 2026-09-28. Designed by Claude, Fable and Astra over four
rounds (Plan 3, rounds 3 and 4) and approved by the owner with the defaults
below: caps pause the run (`cap-pause`), `cap-stop` stays for unattended runs,
and after a stop or a seal the same run continues (`swarm.sh resume`), its old
seal valid as a prefix, a signed v1 kept as it is and the continuation adopted
through a later version. It is the second part of Phase 1a, after the question
register ([ADR 0011](0011-questions-are-a-register-with-their-askers.md)).

## Context

- An answer was an answer, or `inconclusive`. A search that found nothing was
  an `absence`, and a question's answer resting on one alone was
  examination-limited; nothing said over what the search ran, whether it read
  every object it named, or whether the event would have left a trace there
  at all. "Nothing found" read in reports as "it did not happen".
- A lead closed `negative` after one job over one object a minute after it
  was claimed looked the same as one closed after a planned sweep.
- The critic's act on a negative was an attest like any other: "I re-read the
  job's output" said nothing about whether anyone had challenged the
  detection assumptions or tried another route.
- A cap or the wall clock ended the run: the harness wrote the sentinel two
  minutes after the steer. On a long case the operator lost the run at the
  moment the case was nearly answered, and a subscription run had no dollar
  brake at all unless one was given.
- A run that ended was over. Further questions meant a new run, a new copy of
  the evidence, a new custody and new releases; what the first run learnt was
  a prior ledger of hypotheses at best.

## Decision

1. **Results.** A question's answer carries `result`: `established`,
   `partial`, `bounded_negative`, `not_determinable`, `out_of_scope` or
   `premise_not_supported`. It is required on a new answer to a question; an
   answer recorded before it reads as it always did, and `inconclusive: true`
   is taken as `not_determinable`. `established` and `partial` rest on a
   standing finding. The answers check maps results onto its existing
   outcomes, so the finish line and old goals are unchanged: `established`
   and `premise_not_supported` answer the question; `bounded_negative`
   answers an existence question only under the stronger bar (complete
   coverage with the trace expected, reviewed, and the answer saying the
   event did not happen), and is examination-limited otherwise;
   `not_determinable` is inconclusive; `partial` and `out_of_scope` are
   limited. It also names each question's **disposition under the bar**
   (below): what a run may end on.
2. **Run outcomes.** `completed`, `examination_limited`, `paused`, `stopped`,
   `abandoned`, `verification_unavailable`, read from the run's files
   (`runOutcome`). An operator's stop of a run with no sentinel writes
   `done/STOPPED`; a sentinel the harness wrote at a cap reads as `stopped`.
   `stopped` is never `completed`.
3. **Coverage is a ledger kind of its own**, `coverage`, not fields on
   `absence` and answers. A `not_determinable` answer often has no absence at
   all; one negative usually spans several searches, each its own absence or
   limitation; and the review is of the whole search, which needs one entry
   to attest. The record carries the proposition, the objects (refs), the
   time range, the method and settings, what was actually covered, what was
   skipped and what failed, the results (`result_refs`), what is still open,
   and the detection opportunity (`trace_expected: yes | no | unknown` with
   why). Its free-text fields are bounded and refused past the bound, never
   cut. Every material `bounded_negative` and every material
   `not_determinable` cites one that names its question.
4. **The hub computes object coverage.** It stamps the inventory revision
   (the sha256 of `inputs.json` and the catalogue's generation records) and
   compares every object the record names, by digest where it has one,
   against the inputs the jobs behind its results declared: `complete` when
   every object was given to a job, `partial` with what was not. A job over
   everything covers each object and is said to. It counts; it never judges
   whether an object was relevant.
5. **Route plans.** A lead under a question carries `routes: [{source,
   method}]`. The spec said "warn, then require for material questions"; the
   sound reading against the register is: the first lead under a question
   without a plan is warned; the first lead under a person's question must
   carry one (it is the lead that states the proposition and its negation);
   a negative close of a material lead, or of any lead under a material
   question, is refused without one, and a material negative answer is
   refused when no lead of its question planned a route. At a negative close
   the hub lists the planned routes no job of the question's leads declared
   and no coverage record names (`not_examined`). A route named in words
   only is kept and said to be untrackable.
6. **Quick negatives.** A negative close held two minutes or less, after one
   job over one object (and no job over everything), is flagged
   `quick_negative`: in `leads.md`, in the header until a peer attests the
   negative, and in the report. It is a review cue, not a refusal.
7. **Peer review of material negatives.** A material negative (the answer,
   or its coverage record) stands "negative (unreviewed)" until a seat that
   recorded neither attests it with `review`: whether it challenged the
   detection assumptions, reproduced a decisive check, and tried a
   materially different route, each done or not, with what was done or why
   not. The finish line refuses while one is unreviewed; the review counts
   as the critic's act.
8. **Wording.** The report renders a bounded negative as "No evidence that X
   was found in <objects, time range>", with its coverage. "X did not
   happen" (`asserts_absence`) is taken only on an existence question,
   resting on coverage the hub found complete whose detection opportunity
   says the event would have left a trace; the record refuses it otherwise,
   and the answers check names an answer worded so without the bar
   (`wording`).
9. **Operator acceptance.** `swarm.sh question <run> accept Q-n --as
   bounded|not_determinable --why --expect-rev N` is revision-bound; it is
   refused while a lead under the question is open or its negative is
   unreviewed, and any acceptance makes the run `examination_limited`.
10. **Stop policy.** `--stop cap-pause|cap-stop|operator`, default
    `cap-pause`; `--until-solved` is `--stop operator`. The caps and their
    defaults: the wall clock keeps its default (8 minutes under ten agents,
    15 at ten, 20 at twenty), and a metered team without `--cap-tokens` gets
    100,000,000 tokens as a second brake (a seven-agent case runs to tens of
    millions, so it stops a runaway, not a case); a team whose dollars are
    not charged still has to give its token cap. Under `cap-pause`, at a cap
    the seats are steered to post a checkpoint, and two minutes later the run
    pauses: `budget.json` records the pause; no model call goes out (the
    extension's `context` hook holds it on the host, the model gateway
    refuses it, the hub prompts no seat, and the watchdog enforces the pause
    from outside the panes); the partial result stays as it is; the operator
    is notified (`paused`). `swarm.sh extend <run> [--minutes N] [--tokens N]
    [--usd N]` lifts it when the caps then leave room, and the watchdog wakes
    each seat once; `swarm.sh stop` ends it as `stopped`. The time a run is
    paused, or stood stopped, does not count against its wall clock. The run
    never goes on by itself, and the operator's silence approves nothing.
    `--stop operator` (and `--until-solved`) takes the caps and the wall
    clock away, and nothing else: it adds no stricter answer requirement
    (see "The end of a run" below).
11. **Diminishing returns.** When no new finding, question disposition or
    coverage record has appeared across 20 committed jobs or 30 minutes
    (`SWARM_YIELD_JOBS`, `SWARM_YIELD_MINUTES`), the watchdog proposes a stop
    to the operator as an operator request of kind `decision`. It is never
    an agent's vote, and it stops nothing.
12. **Resume.** `swarm.sh resume <run> [--question TEXT … | --questions FILE]
    [--as ID]` (and "Continue this run" in the console) continues a run that
    ended: the same sandbox, the same ledger, registers, board, trace and
    store journal, appended to and never rewritten. Nothing moves until the
    budget holds: the wall clock counts on from the stop, the caps grow by
    what is given, and a resume that would still be over a cap is refused.
    What marked the end moves whole to `done/history/<k>/`, the first
    segment's VM records and kept disks aside; each seat starts from its last
    hand-off note or compaction summary, whole, and the registers as they
    stand; the questions given are admitted as analyst questions. The resume
    is the operator's act, recorded on the trace, the operator's record, the
    registry, `budget.json` and the custody anchor beside the run, with each
    chain's length and head. The next stop seals the continuation anew: a new
    custody verdict and a new draft release. Every earlier verdict the anchor
    names verifies as a prefix of the chains, and `custody-verify` shows each;
    a release verifies with its chains as a prefix only when the anchor
    records a resume after it. A signed v1 stays untouched and valid for what
    it bound; the continuation's answers are adopted through a later version.
    The kickoff keeps its own options outside the run (0600), so the resume
    restarts the same team; a run started before that gives them after `--`.

## The end of a run, under every stop policy

A generic DFIR platform must allow a question to have no answer: the
pressure goes on coverage, never on answers. And "until examined, within
budget" (joint-r3, Phase 1a): a quick "looked, not found" must not end a run.
So there is one rule, under every stop policy: `done` finishes a run only when
every question in scope has a **disposition under the bar**, no material
lead is open, no defect stands (a defect a limitation only names included:
a defect is fixed) and the goal's checks are met. The dispositions are:
established; partial; `bounded_negative` resting on a coverage record
another seat reviewed; `not_determinable` resting on one likewise; a
premise shown not to hold, on a finding; out of scope; accepted by the
operator; withdrawn. A best candidate is none (B2), and neither is an
answer resting on a limitation alone, a negative whose coverage no longer
stands, or a question behind a quick negative nobody has attested. The run
ends `completed` when every question is established or settled by a
bounded negative that says the event did not happen under the stronger
bar, and `examination_limited` when any is not determinable, partial,
out of scope, a bounded negative short of that, or accepted.

The stop policy decides only who else ends the run, and when a cap pauses or
stops it. Under `cap-pause` and `cap-stop` a cap pauses or stops the run
whatever the questions' state, and the operator may stop it; that end is
`paused` or `stopped`, never `completed`, and an agent may still abandon
(`abandoned`). Under `--stop operator` (its alias `--until-solved`) there is
no cap and no wall clock, nobody abandons, and nothing but the finish or the
operator ends the run; it adds no stricter answer requirement: a reviewed
`not_determinable` ends it examination-limited, as it ends any run.

Until 2026-09-28 the rule differed by policy. `--stop operator` still
carried the ctf12 rule ("every question answered, an examination-limited
finish is not accepted"), which left the operator's acceptance as the only
way to end a run on a question the evidence could not answer (the CTF pilot
on the integrated branch showed it). The cap policies went the other way: a
limitation that merely named an unanswered question let the agents finish,
examination-limited, with no coverage record and no review: the shallow
negative this record exists to prevent. Both were replaced by the one rule.
The checks report the dispositions (`dispositions` in the answers check's
machine line, `disposition` on each question of the finish gate, `holding`
for a defect a limitation only names); the contract's Questions section,
the worker prompt and the refusal tell the agents the path to a
disposition when a question cannot be determined (plan the routes, record
the coverage, have another seat review it, answer `not_determinable`), and
the refusal names each question with none and what blocks it. A goal whose
answers check runs in report mode (`--report`, an older goal) reports no
dispositions: its questions end answered, and otherwise the run ends by its
stop policy.

## After review

An independent review (Astra, of the commits that built the above) found
seventeen ways around it; each has a test that failed before its fix.

- A coverage record binds its results by hash: a result superseded,
  disputed or changed takes the record, and a review of the negative
  resting on it, out of standing (`coverage_stale`).
- `premise_not_supported` rests on a finding. "It did not happen" is held
  whatever the result. The report states a negative's conclusion from the
  coverage record's proposition and scope, never from the agents' words.
- An acceptance is of the answer that stood (its hash), and an accepted
  question's negative is held to the bar all the same.
- The hub names objects as the job scopes do (a digest, a store path, a
  catalogue directory), and a coverage record may name a directory.
- A release's chains are verified with their own verifiers; only a resume
  anchored at a boundary those chains hold relaxes a release to a prefix;
  the report bytes a release binds are kept at `release/bound/<sha256>` when
  the run is resumed; a gone gateway log breaks an earlier seal; the resume
  is anchored before anything moves.
- A compaction is held while the run is paused, and so is the model call
  whose check wrote the pause. An extension reads the run's end under the
  lock a stop takes. The operator is told of a pause once, whoever wrote it.
  The watchdog runs at `--idle-nudge-sec 0` too, for the stop policy, and a
  wake that did not land is tried again.
- The start options kept for a resume never hold the notify command, and
  hold an `--env` value only where no pane can read it; the stores are
  denied to a host run's panes where the guard can. A resumed run's
  evidence image is attached again and held to its manifest.

## After the first calibration run

The first calibration case run on the new flow (a synthetic departure case
with a truth file kept outside the repo) scored the swarm against what the
evidence holds. It missed a third of the facts that sit in deleted and
unallocated space; answered "every file" and "every connection" established
with no coverage behind them; adopted a decoy at high confidence, attested
established; stated every answer high (four of them wrong); answered a
question that needed a source the evidence did not hold not_determinable,
with no acquisition ask; and left a question not_determinable after the
evidence that settled it was added late. Five rules follow, each generic
(no tool, no file system, no case named) and each tested.

- **New evidence stales what rests on older coverage.** An evidence
  addition makes stale every standing `bounded_negative`,
  `not_determinable` and `partial` answer (and a premise rejected on a
  search alone) whose coverage records were recorded before the addition's
  ledger entry, and those records, whether or not the operator named the
  question. The gate holds each (`evidence_stale`: "new evidence since its
  coverage (ev-n); re-examine against it"). It clears only when the new
  evidence was examined for the question and another seat reviewed that
  examination: the answer cites a coverage record for the question recorded
  after the addition's entry that names the import among its objects and
  that another seat attested, or cites an entry other than a coverage
  record that rests on the import (its refs, results or jobs name it) and
  that another seat attested. A review made before the evidence came counts
  for nothing on an answer recorded after it. The Fable review of the
  batches found the first form of the rule cleared by one unreviewed line
  and a re-record resting on the old review. The operator's lever is the
  acceptance: one made after the addition's entry (it records the ledger's
  head, `ledger_seq`) excuses `evidence_stale` on its question; one made
  before does not, nor does it excuse evidence added after it, and the
  acceptance's reply says what the finish line still holds on the question
  (`still_held`: every defect an acceptance never excuses).
  `evidence add` and its board post name the answers
  it stales. An established answer is not staled. The order is the
  ledger's (the addition's external entry against the records' seqs), not
  the inventory hash: a catalogue generation moves the hash too. In the
  calibration run the answer that stayed wrong had been recorded again after
  the addition, on reviewed coverage that named the new evidence, so this
  rule would not have held it: it makes the re-examination of every other
  negative explicit, and a re-examination that misreads the new evidence is
  the review's to catch.
- **A completeness claim rests on coverage of its areas.** A question whose
  words ask for every one, all, each, or a complete list, set or inventory
  is marked `completeness` in the register when it is opened (a small word
  rule; "at all" does not count), and an asker sets it either way
  (`question add --completeness`, `--no-completeness` on amend; an agent's
  `question_open` takes `completeness`). An established or partial answer
  to such a question rests on a standing coverage record for it that names
  its `areas` {allocated, deleted, unallocated, slack, secondary}, each
  searched, skipped or not_applicable, with what was skipped said in
  `skipped`; without one the gate holds it as it holds an uncovered negative
  (`completeness_uncovered`). The areas are generic: an area the evidence
  does not have is not_applicable.
- **An established attest names an alternative.** An attest with strength
  established carries `answer_review.alternatives` as `[{explanation,
  why, evidence}]`, at least one alternative explanation the reviewer
  weighed, why the evidence rules it out, and the entries that show it
  (E-<seq>, each checked against the ledger). An alternative counts only
  with an entry named, and with an explanation and a why that are neither
  empty nor a placeholder nor the same words (`alternativeCounts`: a
  structure first, a short stock list second; the Fable review of the
  batches passed `[{explanation: "none", why: "n/a"}]`). One without an
  alternative that counts is recorded best_candidate, with the reason in
  `capped`, and the reply says so. Nothing is refused, and the
  seat may attest again once it has weighed one (a later established review
  by the same seat is recorded; any other repeat is not). A text
  `alternatives` is still read, as an older review's and a best candidate's.
- **Confidence is recorded, not only stated.** An answer keeps confidence
  high only when it is established and another seat attested it
  established naming its alternatives; any other high is recorded medium,
  and the reply to the answer says why. Nothing is refused, and the stated
  confidence stays in the chained entry: the recorded one is derived where
  it is read (`recordedConfidence`), because the attest that keeps a high
  comes after the answer. The report, the metrics (`confidence`) and the
  calibration score show the recorded confidence, the stated one beside it.
  The rule reads only answers recorded under it: the hub writes
  `confidence_rule: 1` into the chained core of every answer to a question
  that states a confidence. An answer without it was recorded before the
  rule and keeps the confidence its author declared, and the report and the
  metrics say "as declared: recorded before the run recorded confidence"
  (the Fable review of the batches found every high of every finished run
  lowered). The ledger version could not tell the two apart (both are 4),
  and the harness commit is the registry's, not the run's, and commits are
  not ordered.
- **A missing source is asked for.** When a question needs a source the
  evidence does not hold, the agents open an acquisition ask
  (`lead_close needs_operator` with `ask.kind: acquisition`) before
  answering it not_determinable, and the coverage record behind the answer
  names it (`acquisition_ask: R-<n>`) or says why none would settle it
  (`acquisition_none_why`). The gate warns, and does not hold, when a
  not_determinable answer's coverage does neither: the answers check prints
  a `WARN:` line and its machine line carries `warnings`, which the finish
  line's note repeats.

## After the round-13 scoring

A later scoring round found the negatives passing their bar and still wrong.
On one case five questions were answered not determinable, all false
negatives; for two of them the answer's row sat in a parser export the run
itself had made half an hour before the answer, and each had passed a review
or rested on a reviewed coverage record. The records named two or three
sources, and the reviews checked each answer against that narrow coverage,
never against what the run's store already held. On another, a correct
established answer was walked down to not determinable by a dispute that
cited nothing against it.

- **The store sweep.** A coverage record names `looked_for`, the literal
  strings a hit would contain were the answer in the evidence, or
  `looked_for_none_why`. When the record is written the hub searches every
  output the run holds for them (job outputs and logs, imports with the
  evidence added late among them, captures, the whole outputs kept under
  `tool-output/`; not the input images, which the record's own search
  covers): bytes and strings only, ASCII case folded, UTF-8 and UTF-16LE,
  every file streamed whole, no parser and no per-tool code. The record is
  immutable and the sweep takes time, so its result is a chained line of its
  own (`ledger/sweeps.jsonl`), bound to the record's hash; no line is
  pending. A negative waits for its sweep as for a review (`sweep_pending`);
  a hit in an object the record does not name holds it until the record is
  revised to name that object, with what it showed, or the answer is revised
  (`sweep_hits`); a sweep its budget left partial names what it did not
  search and holds until the operator accepts the question's limits
  (`sweep_partial`). A hit in an object the record names (its refs, or the
  outputs among its result_refs, since a search's own output echoes what it
  looked for) is said and does not hold: the review is where an answer that
  misreads the objects it names is caught, and the review offer now carries
  the sweep, named hits included, and asks for the answer to be checked
  against the whole store. The calibration run's late false negative was
  this case: its revised coverage named the new evidence, so a sweep's hit
  there would be a named one, shown to the reviewer rather than holding.
  An object made from the run's own words (a dump of the ledger, a seat's
  compaction summary, a search that asked for the string and read only
  what is accounted for) is an echo, named on the line and holding
  nothing; see "Echoes: authored, not derived" below.
- **A downgrade needs counter-evidence.** A revision from established or
  partial to not determinable or a bounded negative carries `downgrade:
  {evidence, why}`: the entries or objects that undermine the earlier chain.
  Without it the revision is refused, and the refusal points to the
  alternative: dispute the answer, and if the doubt stands lower its
  strength to best_candidate or its confidence to medium; the answer stays.
  The report's chain for the question shows the earlier answer, the disputes
  on it and the downgrade's evidence.

The sweeps are a register like the others: custody seals
`ledger/sweeps.jsonl` by its length and head, a release binds it in its
chains, a package carries it (`ledger-sweeps.jsonl`, its lines redacted
by their hashes under `--redact` when they say a sensitive entry's words or
sweep a sensitive record), and `custody-verify` and the package's `verify`
walk it; `scripts/chained-registers.ts` keeps the list of every chained
register, and a test fails on one it does not name.

## The provider's limit, and the operator's pause

A run under `--stop operator` hit its model provider's subscription usage
limit on every seat at once. Each turn ended in the provider's words ("You
have hit your ChatGPT usage limit (pro plan). Try again in ~6904 min.",
"Codex error: The usage limit has been reached"), recorded as `agent_error`,
and the watchdog prompted each seat again, half an hour apart, for days,
while every VM and the hub stayed up; the operator was never told the run
could not go on before a stated time. A cap's pause did not apply: nothing
was over a cap, and the policy had none.

- **A pause that is not a cap.** `paused.reason` is `provider_limit` beside
  `cap` and `wall_clock`, and it pauses a run under every stop policy. The
  pause keeps the provider's distinct error texts, whole (`detail`), the
  models refused (`models`), and the end it holds to (`until`, below). A
  wait is read from the words: "try again in ~N min", "in N minutes", "in N
  hours", "retry after N seconds", a Retry-After number, the first time with
  its zone that is still ahead; a wait of more than 30 days (an epoch sent
  where seconds were meant) is not taken for one. Nothing else about a
  provider is read.
- **Every seat is retried.** A seat whose last turn ended in a provider
  error is prompted again by the watchdog with backoff (each wait twice the
  last, up to half an hour): until solved, for as long as the run goes;
  under `cap-pause` and `cap-stop`, three times per run of errors, within
  the wall clock. Before, only an until-solved run retried, so the second
  half of the rule below could not hold under a cap policy.
- **The rule.** The watchdog pauses the run when every live seat (not done,
  not dead, and reached by the last lift's wake) has, as its last own row
  since the last lift, a provider error, and every one of those seats is
  limited by its own evidence: its errors state a wait of 30 minutes or more
  still ahead, or it was prompted again after its first error and refused
  again (a prompt's row may land up to five seconds after the refusal it
  caused). One seat's error never pauses the run, and neither does one
  seat's long wait beside the others' passing errors: those are retried.
  The harness's own rows under a seat's id (a prompt's echo, a lost hub
  link, an extension's error, a stop) are not turns. The rule is read again
  under the table lock the pause is written under, as a cap is, so two
  watchdogs never both act and a seat that came back leaves the run going.
  Each failed turn is on the trace once, whole (a retry that failed on the
  same words used to leave no row).
- **The end it holds to.** When every limited seat is on one provider (the
  part of its model before the slash), `until` is the longest end any of
  them was told: every seat on a provider uses the one credential the run's
  Pi store (or the key the kickoff was given) holds for it, so its limit is
  one limit, and a try before its last named end would only be refused. In the run above one seat said ~6904 minutes
  and the others named no time; the pause holds to the 6904 minutes. When
  the seats are on several providers, `until` is the earliest end if each
  was told one (the first time any seat can go on), and otherwise there is
  none and the harness tries every half hour.
- **While it holds** every brake of a cap's pause holds: no seat is
  prompted, no model call goes out, the wall clock does not run, and the
  watchdog's provider-error prompts stop.
- **The harness tries again** at `until` and a minute, or half an hour after
  the pause when no end is known: it lifts the pause (`resumed_by:
  harness`, `run_unpaused` on the trace) and wakes each seat once. If every
  seat is refused again, the same rule pauses the run again; a pause that
  follows the harness's own try, no seat having worked since, continues the
  same spell (`since`) and does not charge the try to the wall clock. A seat
  the wake could not reach, with nothing of its own since, is left out of
  the rule until the reaper marks it. The operator is told once per spell,
  with the end the provider named and the advice: a long wait holds every
  VM; to free the machine, stop the run (custody seals it) and resume it
  after the limit lifts. The board is told the same, once, in one line. A
  seat tells the board of its own provider error once per spell of failed
  turns, and not again for the error it last told, its numbers and times
  masked: a countdown ("~6904 min", then "~6874 min") put one post per seat
  on the board at every try.
- **The operator's pause.** `swarm.sh pause <run> [--why TEXT]` holds a
  going run under any stop policy (`reason: operator`), and `swarm.sh
  unpause <run>` (the console's Unpause beside the pause) lifts a pause
  whose cause is gone: the operator's hold and the provider's limit always,
  a cap's pause only when the caps leave room, and otherwise it is refused,
  pointing to `swarm.sh extend`. An extension does not lift a pause that is
  not a cap's. Both are on the operator's record and the trace.
- **The run's end in a pause.** A run stopped while paused keeps the pause
  it was stopped in: the harness's try is not made on it (the stop is read
  under the lock the lift takes), and a resume folds the pause into the
  history as the resume's (`resumed_by: "<by> (resume)"`), which wakes no
  seat, since the resume starts each from its hand-off. A run whose seats
  all died while paused (`done/ALL_AGENTS_DEAD`) has no outcome of its own,
  as one that died unpaused; neither is shown as paused, and the console's
  elapsed time leaves every pause out.

## After the runs s9722fa and sb1b3c8

Two real runs on the CTF preset (`--more-evidence no`) walked around the
rules above from the other side. On s9722fa (six goal questions, `--stop
operator`) every question had a partial answer resting on findings; once
readiness had held all six as best candidates (ADR 0015, "After the run
s9722fa"), the seats revised every one to not determinable with a
`downgrade` whose evidence was limitations, the downgraders' own coverage
records and findings that contradicted nothing, and moved their standing
findings into the reasoning. The case lost every positive answer; the
round before had three correct and two partial. On sb1b3c8 seats cleared
`sweep_hits` by writing a revised coverage record whose refs named up to 66
hit objects (by their jobs' directories), with nothing recorded about what
any of them showed. On both, seats opened acquisition asks in the finish
tail only to satisfy "a not_determinable names its acquisition ask", and
the case policy declined each at once.

- **A downgrade's evidence bears against the chain.** The earlier chain is
  the earlier answer and the entries it rests on (its support). At least
  one entry of `downgrade.evidence` bears against it: a finding or an event
  that contradicts the answer or an entry it rests on (`rel` contradicts),
  a hypothesis refuted that names one of them (`rel`) or corrects one, an
  entry it rests on that a dispute in force or a standing finding or event
  contradicts, or a correction (supersedes, at any depth) of one. A
  limitation says a route could not be examined, and a coverage record what
  a search covered: neither undermines a finding that stands, and an
  object alone says nothing until an entry says what it shows. The refusal
  names each entry given and why it does not bear (`downgradeCheck`).
- **A standing finding is never discarded.** While a positive finding the
  earlier answer rested on (a finding or an event it cites, recorded for
  its question) still stands, not corrected, under no dispute in force and
  contradicted by no standing finding or event, a revision to not
  determinable or a bounded negative is refused whatever its evidence. The
  refusal says to answer partial (the established parts stated, the open
  parts named with their limitations and coverage) or, if a finding does
  not hold, to say so first: dispute it, correct it, or record the finding
  that contradicts it. The spec named not determinable; a bounded negative
  after a positive answer discards the same findings, so the rule holds
  for both. The dispute path is unchanged: a doubt is a dispute, and the
  answer stays.
- **Naming a hit is not examining it.** An object an earlier sweep for one
  of a coverage record's questions found a hit in, which the record now
  names (in refs, a directory holding it included, or among its object
  results), is cited in its `result_refs` by an entry that interprets it: a
  finding, an event, an absence or a limitation that stands, names the
  object itself in its refs (a directory does not count), and was written
  after the sweep that first found it. One entry per object, or one absence
  whose refs list several. Until then the gate keeps holding it as
  `sweep_hits`, naming each object, the strings found in it and the record
  whose sweep found it, and the coverage record's reply says it when it is
  written (`unexaminedHits`, store-sweep.ts). Object refs and times only:
  nothing is read or judged. It applies to a record whether or not it
  names `looked_for` itself, so dropping the strings does not clear it.
- **No ask to satisfy a rule.** Under the case policy's `more_evidence: no`
  an ask is declined at once, so `acquisition_none_why` naming the policy
  satisfies "a not_determinable names its acquisition ask": the
  `no_acquisition_ask` warning and the answer's reply give that wording
  (`NO_MORE_EVIDENCE_NONE_WHY`) and no longer suggest an ask. Under `ask`
  and `yes` they say what they said.

## After the run s993d40

On s993d40 (a CTF case of six questions) all six answers stood partial.
Two were complete answers whose only hedge was whether the person the case
brief names did it personally, which the brief states as given; both were
attested established by two reviewers while still labelled partial, each
review holding that one part open as the answer declared it. A third
answer left out two methods the ledger already held as findings, attested
by another seat, under that question's leads.

- **A case premise is not a part to prove again.** What the case brief or
  the goal states as given (who the subject is, whose device it is, the
  scenario's facts) is a premise of the examination. The answer names the
  premise it relies on, in its reasoning or limitations ("rests on the case
  premise that …"), and is established on the evidence for the rest. An
  answer is partial only for a part of the question it could not establish,
  and a review does not hold a premise open. When the evidence contradicts
  a premise, that is `premise_not_supported` or a finding, never a silent
  hedge. The worker prompt, the `record` tool's answer and `result`, and
  the `attest` tool's parts say it. The harness cannot tell a premise from
  an open part without reading words, so this is the agents' rule; the
  gate warns only of the shape it can see:
  `partial_all_parts_established`, a partial answer every review of which
  holds every part it weighed established, one of them attesting it
  established. The warning asks the recorder to say which part is open or
  to record the answer established. It would not have fired on s993d40,
  whose reviewers held the premise open as the answers declared it: the
  words are the fix there, the warning the backstop.
- **What the question's leads established is in its answer, or said not
  to bear on it.** The lead register knows each lead's questions and the
  entries recorded under it: those that interpret a job run under it, and
  those a close or a confirmation of it names (its ref and its
  `result_refs`), every close in its history included
  (`questionLeadEntries`). A standing finding or event recorded there, not
  disputed, that another seat attested or two seats recorded, and that the
  question's standing answer does not reach, directly or through the
  entries it cites (support, contrary, limitations, a downgrade's
  evidence, then `rel`, a coverage record's `result_refs` and
  `result_bound`, and a cited answer's own citations: `answerReach`), is a
  warning, `lead_findings_uncited`. It lists every such entry by `E-<seq>`
  with its leads: "established under Q-n's leads and not in its answer:
  cite them or say why they do not bear on it". Registers and refs only,
  nothing read of what an entry says; nothing capped. Over s993d40's
  registers it names two entries, on that one answer alone.
- **A warning never holds.** Both are the gate's warnings, as
  `no_acquisition_ask` is: a `WARN:` line of the answers check, its
  machine line's `warnings`, the finish gate's, the verdict's note, and
  now readiness, apart from its items, so `finish status` shows them to
  the coordinator before its done. None makes readiness not ready or
  refuses a done. (Since then they are delivered where the decision is
  made: the next section.)

## Warnings where the decision is made

The three warnings were said in the answers check, the finish gate, the
verdict's note and `finish status`: to the coordinator, at the end, after
the seats that could act on them had moved on. On s993d40 the reviewers who
held a partial answer whole, and the seat that recorded an answer leaving
out what its question's leads had established, were told nothing at the
moment they decided. The brainstorm of 2026-09-29 (L3) agreed to make the
existing warnings land where the decision is made, and to measure that,
before any new rule.

- **Four points, never blocking.** Each point asks the same gate over the
  same inputs as readiness, for the questions readiness reads, and says the
  warnings in the words `finish status` says them with (`finish.ts`
  `warningsAt`, `gateInputs`; `protocol.ts` `warningWords`):
  - the reply to the record that writes a question's answer: every warning
    on that question (`warnings` in the reply; their codes, `warned`, on
    the trace);
  - the review offered for the answer, as the offer reaches its seat, and
    the reply to an attest: on the answer, on a coverage record a negative
    answer rests on (each negative resting on it), or on an entry a warning
    names (an entry an answer leaves out, now held by two seats). Reviews
    are offered to one seat for a limiting route and a material negative
    only (ADR 0015); an established or partial answer has no offer, so its
    reviewer is told in the reply to its attest. `partial_all_parts_established`
    is made by the reviews, so the first point that can say it is the reply
    to the attest that makes it;
  - the reply to a lead's close, or to a confirmation of one (the closer's
    `lead_confirm`, one lead or a batch): the warnings of each question the
    lead serves that the act changed, by what it recorded under the lead
    (its ref and results), as they stand after it. The gate is read twice
    on one snapshot, with the act's events and without them, so nothing
    else that moved meanwhile is laid at its door (`closeChanged`); a close
    that changes nothing says nothing. On s993d40 the closes of question
    6's leads after its answer and its reviews added the two entries two
    seats held there (E-84, E-93) to its warning, and only those closes'
    replies and finish status said them;
  - `finish status`, as before.

  A point says what the gate warns of at that moment. A warning that
  arises later (a finding attested after the answer) is said at the next
  point that bears on it, and always in `finish status`. A warning is
  never a refusal and never an item.
- **What the record ties to a question, wherever it was recorded.**
  `lead_findings_uncited` covers every standing finding or event, under no
  dispute in force, that the question's answer does not reach and that is
  tied to the question:
  - one two seats hold (a second author, or another seat's attest) that
    the lead register recorded under a lead of the question, or that
    names the question in its own `answers`, or whose `rel` supports or
    contradicts an entry the answer cites, or weighs late evidence
    against it (a delta kind; `answerCites`: its support, contrary,
    limitations and a downgrade's evidence, the correction standing for
    each): a `rel` that `duplicates` an entry or is `derived_from` one
    says what it repeats or comes from, and ties it to nothing (the Fable
    review of the limits branch);
  - one seat's, only when it names the question in its own `answers` and
    another question's standing answer relies on it (reaches it, directly
    or through what that answer cites): its author tied it to this
    question, and the record already rests a conclusion on it. The
    motivating case is of this shape: a method established under another
    question's lead, which that question's answer cites.

  One seat's entry that no answer relies on does not count, and neither
  does one tied by a lead or by `rel` alone (`questionUncited`). Counting
  every finding a seat tags with a question (a rule tried on this branch
  and replaced) warned every question of s993d40 and of sa2f2f2, up to 18
  entries each: warning fatigue. Each entry is listed with its tie:
  "under L-n", "that names Q-n", "whose rel supports E-m, which the answer
  cites", or "that names Q-n, held by one seat, relied on by the answer to
  Q-m"; the warning reads "answer #n (question:q) leaves out what the
  record ties to Q-q: …", every entry, however many. A lead register whose
  chain is broken says nothing of the leads; the ledger's own ties still
  count. Registers and refs only, nothing read of what an entry says.
- **Replayed** (this checkout, values-free, entries by id):
  - s993d40. Q-1: 4 (E-20, E-31, E-36, E-75), one seat's, relied on by
    the answers to Q-2 and Q-6. Q-2: 4 (E-10, E-13, E-16, E-35), one
    seat's, relied on by Q-1's. Q-3: 1 (E-57), relied on by Q-5's. Q-4: 6
    (E-57, E-84, E-85, E-86, E-91, E-92): E-84 two seats' (established
    under question 6's leads, naming question 4), five one seat's relied
    on by Q-1's, Q-2's or Q-5's. Q-5: 2 (E-96, E-98), relied on by Q-4's.
    Q-6: 9 (E-10, E-13, E-15, E-18, E-22, E-30, E-35, E-84, E-93): E-84
    and E-93 two seats' under its leads, seven one seat's relied on by
    Q-1's, Q-3's or Q-5's.
  - sa2f2f2. Q-1: 4 (E-26, E-29, E-31, E-35), relied on by Q-6's. Q-4 and
    Q-6: 1 each (E-82), relied on by Q-5's. Q-2, Q-3 and Q-5: none.
  - Under the two-seat rule s993d40 warned Q-4 (1 entry) and Q-6 (2) and
    sa2f2f2 nothing; counting every finding a seat tags warned 46 entries
    on s993d40 and 55 on sa2f2f2; this rule, 26 and 6. Whether the answers
    get better for it is for paired runs.
- **Request guidance.** Under `more_evidence: no` nothing suggests an ask
  (verified; the rule is "No ask to satisfy a rule" above): the record's
  reply, the warning and the prompt give `acquisition_none_why` naming the
  policy. A value read from an image is cited from the output of a job
  that read the image (an OCR tool run over the input), never from a
  transcription typed into a command: the network's refusal said so (ADR
  0012); the prompt and the `net_request` tool say it now. A question put
  to the operator (a `needs_operator` close that is not an acquisition)
  says what observation would settle its question and what each possible
  answer changes (which answer, to which result): the prompt, the
  `lead_close` tool and the close's reply (`guidance`) say it. Guidance
  only: the harness does not read a ref's words.
- **Measured, not assumed.** `swarm.sh replay --deliveries` reads, act by
  act, which warnings each point would have carried, on the registers as
  they stood at each act (ADR 0017, "Measuring a rule change"); the
  contract fixtures `warnings-delivered`, `lead-findings-tied`,
  `lead-close-delivered` and `no-ceremonial-ask` hold each point to this
  section. Whether the agents
  act on them is for paired runs: fewer complete answers left partial, and
  no rise in false established.

## A source's broad extraction before a negative on it

On the Belka runs four of five false negatives rested on a row no job had
ever produced. The iPhone's tar was catalogued at the kickoff by the mobile
pack's recipe, which inventories the tar and "parses no artifact content",
and then read narrowly, one database at a time; the whole-source parse the
pack's own programs can do was an agent's choice that nobody made. The hub's
object coverage called a search complete as soon as a job had declared the
tar. The brainstorm of 2026-09-29 (L1) agreed that the packs say which of
their recipes parse a whole source, that the harness offers that work per
source and records what became of it, and that the reviewer of a negative
reads that first. Whether a negative waits for it was left open; the call
recorded with the limits plan is the narrow one: only a negative that
claims absence, or claims complete coverage over the source, waits, and
only while the extraction is under way.

- **What a pack declares.** A recipe says its `purpose`: `inventory` (it
  lists what a source holds) or `broad_extraction` (it parses the whole
  source into a searchable form). A broad extraction names the
  `capability` it prepares and lists its `exclusions`, what it does not
  hold; one the job images cannot run says why (`unavailable`), has no
  trigger, and the job service refuses it by name with that why. A recipe
  that says nothing is an inventory. The shipped recipes, read as they are:
  disk-volumes, archive-members, ios-filesystem, android-backup and
  static-binary inventory; memory-windows (the standard views of a memory
  image), linux-target (the Linux artefact plugins over a disk) and
  network-capture (every packet's fields) are broad extractions. New:
  mobile-forensics/ios-ileapp and android-aleapp (every artefact module of
  the pack's iOS or Android parser over a whole file-system acquisition,
  run by the kickoff), mobile-forensics/android-backup-apps (declared
  unavailable: nothing in the mobile image parses an adb backup's app tree
  as a whole, so its preparation is declined, with that why, rather than
  faked), and computer-forensics-base/disk-timeline (a super timeline of a
  whole disk image; hours on a large image, so offered, not run by
  itself). The programs are already in the images; no image changes. The
  harness reads the declarations and names no program.
- **What applies.** The census asks every broad extraction about every
  input whatever its `auto`, and lists each that applies in plan.json's
  `preparations` (the recipe, its capability, whether the kickoff runs it,
  and the pack's why when it cannot run); the input's row and the
  catalogue's README say it. Evidence added later is asked by the system's
  detect pass over each file. A detect pass never runs a broad extraction
  its pack does not mark `auto`, or one that cannot run: the first is
  offered, the second declined, and an agent that asked for the pass is
  told.
- **Offers, one per source digest and capability.** One the pack marks
  `auto` runs without an agent (the kickoff's lane) and needs no offer.
  Every other is offered as a lead of its own (`openPreparationLead`): the
  harness's, unheld, serving no question and not material (it holds the
  finish only through the negatives on its source), with the route
  {source, recipe}, the source among its objects, what it prepares and
  excludes in its why, and the next action, catalog_request with the
  recipe; it is offered to the seat idle longest, as any lead nobody holds.
  It is not offered when the same capability over the same bytes is queued,
  running or sealed, or on the record in any state. The seat that takes it
  runs it, or closes it deferred, infeasible or needs_operator citing a
  limitation that says why it is not run: that is the preparation's
  decline, with the seat's why. A seat's close of it any other way
  (resolved, duplicate, negative) with nothing that ran the extraction or
  runs it now is its decline too, and the receipt says how it was closed
  and that nothing ran it (the Fable review of the limits branch found it
  left no receipt, the hold in place, and a fix that named the closed
  lead). A lead whose extraction reached an outcome by any route (the
  lane, a seat under the lead or not) is closed by the harness, withdrawn,
  citing the receipt, while no seat holds it: a held lead is its holder's
  to close.
- **Receipts, on the store journal.** `type: preparation`, one line per
  step: planned (queued as a job, or offered as a lead), attempted (its
  job started), produced, partial or failed (its job ended: the generation,
  the output manifest's digest, files and bytes, and what this run of it did
  not cover beside what the recipe excludes), declined (declared
  unavailable, refused by the kickoff's queue with the refusal's words, or a
  seat's decline). Each names the source snapshot by digest, the recipe, its
  version and sha256, the capability, the job or the lead, and the
  exclusions. Every recipe job whose recipe is a broad extraction has its
  receipts, whoever asked for it. The hub writes them each round from what
  the job service and the lead register already say (`scripts/preparation.ts
  reconcilePreparation`), each state once: a restart writes nothing twice.
  Produced never means complete: the exclusions say what it does not hold,
  and a module that found nothing wrote no report. No new register: the
  journal is already chained, sealed by custody, bound by a release and
  carried by a package.
- **The hold, `preparation_pending`.** A material negative (a bounded
  negative, not determinable, a premise rejected on a search alone) holds
  while a source's broad extraction is planned or attempted when the answer
  says the event did not happen (`asserts_absence`), or a coverage record it
  cites is complete (the hub's object coverage) and names that source, or
  a directory holding it. It is a defect with its fix: the job to wait for,
  or the lead to run or decline (never a closed one: its close is recorded
  as the decline at the hub's next round, or the extraction is run
  directly), or the operator's acceptance of the question. Produced, partial, failed or declined releases it, and a later
  run of a released capability does not hold again: the hold is a wait on
  work already queued or offered, never a demand that it succeed or that
  anything be found, so partial and not determinable stay honest
  dispositions under every stop policy. The operator's acceptance excuses
  it (it is not among the negative bar's defects an acceptance never
  excuses).
- **The warning, `preparation_missing`.** Every other material negative
  whose coverage reaches a source whose extraction has not produced is
  warned, never held: one that names the source or a directory holding it,
  one that names a member of the source's catalogue, and one that rests on
  outputs made from the source (followed back through the jobs' declared
  inputs, as many jobs as it takes; a job that read everything is traced to
  no source). A held negative is not also warned; once released without
  producing, it is. The warning names each source's state and exclusions
  and is delivered at every point the others are (`warningsAt`: the
  record's reply, the review offer, the attest's reply, finish status).
- **The review packet.** A negative's review offer opens with the state of
  the broad extraction of each source it rests on: held, weighed without
  it, or produced, each with what the extraction does not hold.
- **The finish revision** moves with each receipt (a decline changes no
  job), and only in a run that has one.

Replayed (`swarm.sh replay --prepare-as`, values-free, ADR 0017), on
s5764c4 (Belka): this checkout's census finds two broad extractions that
apply to its evidence, the mobile pack's over the iPhone tar (run by the
kickoff) and the base pack's disk timeline over the laptop's image
(offered as a lead). With both attempted, one of the run's eight negatives
is held: question 4's, whose coverage record is complete over the tar.
Seven are warned (questions 10 and 13 to 18), each reaching both images:
three coverage records name both, four rest on outputs made from both.
The three that name them are partial, and question 4's is the only
complete one that names a source. With both produced, nothing is held
or warned; with both failed, nothing is held and all eight are warned. As
the run was recorded, with no receipt, nothing changes. Whether the offers
and the hold make fewer never-produced misses is for paired runs on a
generated-source fixture and on Belka (the hold arm against offers only).

Not built: an iTunes or Finder backup (a directory of files) as a recipe's
target, since a recipe is asked about one file; a broad extraction in the
derived catalogue's lane (its budget is minutes, an iOS parse is an hour).
Without the job service (a host run, `--no-jobs`) the census runs each
kickoff recipe where it runs, as it always has (memory-windows, with its
four hours, among them), the new parses included, and no receipt is kept:
receipts, offers and the hold are the hub's. The recipes' calls to iLEAPP,
ALEAPP and Plaso are held to the recipe protocol by stand-ins in the
tests; they have not yet run against the programs in the images.

## Late evidence: the reverse sweep and the delta

On the calibration run sb1b3c8 the evidence that settled a question came
late, and the answers stood without it: every stale answer was examined
again on a coverage record that named the import, another seat reviewed
each, and the late fact was still missed, with the import cited 28 times.
The rule above checked that the new evidence was looked at, never what the
look concluded. The brainstorm of 2026-09-29 (L5) agreed on two things: the
addition is the moment to run the store sweep the other way, and the
re-examination says how the new evidence bears on the answer, not only that
it was cited. A blanket hold on every hit in new bytes was rejected (an
echoing query or a broad string would multiply work, and the failure had
the citations already): the hits are delivered, and the delta is what
clears.

- **The reverse sweep.** When evidence is added (`scripts/material.ts`,
  after the addition's external entry), the import's files, and only they,
  are searched for the `looked_for` strings of every coverage record
  standing at the addition (recorded before its entry, not corrected by
  then: `recordsStandingAt`, by seqs alone, so a reconciliation long after
  finds the same records). The search is the store sweep's: bytes and
  strings, in UTF-8 and UTF-16LE, ASCII case folded, each file streamed
  whole. Each hit is bound to the records whose strings it holds
  (`bears_on`). The line is on the sweeps' chain, version 2 with `of:
  "import"`, bound to the addition's external entry by its hash, with the
  records (seq, hash, questions, strings); a version 1 line is a coverage
  record's sweep, read as before (`readSweeps`), and the chain, custody,
  the release and the package carry both.
- **After the addition, a pass at a time.** The sweep never runs inside
  the addition: the addition commits and answers at once, and the sweep
  runs after it, in the hub's background (a round's pass for each addition
  not done, never awaited by the round) or, when the CLI made the addition
  with no hub, as a detached step (`scripts/reverse-sweep.ts`, one at a
  time) that runs passes until nothing is left or the run ends. A pass has
  a budget of its own (`SWARM_REVERSE_SWEEP_MAX_SEC`, 120 s;
  `SWARM_REVERSE_SWEEP_MAX_BYTES`, 2 GiB); what it leaves is named on its
  line (`left`) and searched by the next pass, whose line continues it
  (`pass`, `continues`), at the next round, until nothing is left: an
  object larger than a pass's budget is searched by a pass of its own, and
  one over the store sweep's own byte budget is named and not searched, as
  the store sweep names it. Every line names what is not searched yet. The
  Fable review of the limits branch found the first form awaited inside
  the addition's lock with the store sweep's budget (16 GiB, 30 minutes),
  holding the addition's post, the operator's reply and the hub's round as
  long, and partial for good past it. A pass already recorded is not run
  again; a failure is run again at the next round.
- **Where the hits go.** To the re-examination of the questions they bear
  on, and nowhere as a hold: each pass's board post says its hits by
  question when it completes (each with the records whose strings it
  holds), and what the next pass searches; a stale answer's
  `evidence_stale` says those on its question, first among what to
  examine; and on a question whose answer the addition does not stale (an
  established one, or one examined since), a hit in an object no entry the
  answer reaches names is a warning, `late_evidence_hits`, delivered where
  every warning is (the reply to the record of the answer, its review offer,
  the reply to an attest on it, a lead's close that changes it, finish
  status). A hit is a string a record looked for, found in the new files:
  the entry that names the object says what it is.
- **The delta.** `evidence_stale` clears as before (the new evidence
  examined for the question on a coverage record naming the import, or an
  entry resting on it, reviewed by another seat) and only when the entry
  that examined the import carries a delta: a standing entry recorded after
  the addition whose refs name the import's objects (the import, or a file
  of it), among the results of a coverage record the answer cites that
  names the import and another seat reviewed (its reviewer saw it), or
  cited by the answer (or as its contrary) and attested by another seat,
  with a `rel` to the question's answer (the one standing when it was
  written, or its correction) of kind `supports`, `contradicts`,
  `adds_part`, `irrelevant` (within the question's scope) or `inconclusive`
  (`deltasFor`). A delta on an entry nobody else looked at, beside a
  coverage record somebody did, clears nothing: an `irrelevant` costs the
  same review as any other delta (the Fable review of the limits branch).
  The report's answer chain says each late delta that neither supports nor
  contradicts the answer (irrelevant, inconclusive, adds_part). The rel
  kinds `adds_part`, `irrelevant` and `inconclusive` are new and name an
  answer (refused otherwise, with why); an entry is recorded with them as
  with any rel, in the chained core only when present, so an old entry
  hashes as it did. A `contradicts` delta on a standing answer is an open
  contradiction until the answer is recorded again; the answer may cite it
  as contrary evidence. The defect says what it lacks: the records before
  the addition, those after it that do not name the import, those not yet
  reviewed, an examination with no delta, the entries that interpret the
  import with none, and those that carry a delta outside the reviewed
  examination. The operator's acceptance after the addition still
  excuses it (`acceptanceExcuses`, unchanged).
- **Old runs.** The rule reads the registers as they are, so a run from
  before it replays with its examined-and-reviewed answers stale again
  where nothing carried a delta; replay says so (ADR 0017). A run resumed
  under it meets the same defect, with its fix. The reverse sweep is the
  hub's at an addition: a run from before it has none, and
  `swarm.sh replay --reverse-sweep` computes, in the copy, what this
  checkout's sweep would have found at each addition.

Replayed values-free (`swarm.sh replay --compare <c34c6cb> --reverse-sweep`),
the harness before these rules against this checkout. sb1b3c8's evidence
came at E-20, before the run's first coverage record (E-31): at the
addition no record stood with `looked_for`, so the reverse sweep would have
searched for nothing and delivered nothing, 0 hits on every question. The
coverage records recorded after it swept the import themselves (the store
sweep reads every import): records for questions 2, 3, 4 and 6 found their
strings there, one object each, most of them in the object the record
already named. Under the delta rule the six answers the addition staled
(questions 2, 3, 4, 6, 7 and 8) are stale again, none of their examinations
carrying a delta; questions 7 and 8 lose the partial disposition they had.
s5764c4 and sa2f2f2 hold no evidence addition, and read the same under both
harnesses. Whether the delta and the delivered hits make fewer missed late
corrections is for paired runs (the usb-departure calibration with late
evidence, `late.reflected`), with wrong reversals counted beside it.

Not built: a complete occurrence index of each hit (the sweep keeps the
count and the first offset, as the store sweep does); a hold on hits in new
objects; the delta on a question the addition does not stale (a hit there
is warned of, and an entry that names the object answers the warning).

## Echoes: authored, not derived

On the calibration run sd0e59d the store sweep held three negatives
(`sweep_hits`, questions 2, 5 and 6) on hits in three whole outputs the
harness had kept under `tool-output/`: two seats' shell outputs and one
seat's compaction summary. The swarm spent two done calls and more than
half an hour on them. The seats did what the fix said: each hit file was
sealed as an import (`tool:<seat>/<file>` cited, `import:<job>/<file>`
published) and each revised coverage record named the import. The hits went
on holding. The sweep knew a sealed object by the sha256 its manifest gives
and a kept output by its inode, so the file and the import it was sealed
as were two objects, and the record named only one of them. Read by what
made them, the three files held nothing new: one was a seat's script
printing the run's own ledger (which holds the records' `looked_for`
strings), one re-read a job's log the record named, and one was the
seat's own summary of its context.

- **One object under several names.** A kept output and a job's log are
  known by their inode, and by their content when another object has their
  size (the hash cached by inode, size and time): a kept output and the
  import it was sealed as are one object, and a record that names either
  names both, as "a group is named when any of its names is" always said.
- **Echoes.** A hit is an echo, named on the sweep's line (`echoes`, each
  with what made every name of its object: `origins`, `{name, by, why,
  reads?}`) and holding nothing, when every name of its object was made
  by the run's own words:
  - `registers`: a command whose words name the run's own registers and
    harness files and no other path of the run (the ledger, the leads, the
    questions, the requests, the board, the inboxes, the trace, SWARM.md;
    `RUN_REGISTERS`). What the run says about the case is not evidence of
    it, and a dump of the ledger holds every `looked_for` string by
    construction.
  - `harness`: a file the harness kept from a seat's own model words outside
    any tool call, by one of its own events (the self-compaction's summary;
    `HARNESS_KEEPERS`, which a test keeps equal to the self-compaction's
    events, all of them reserved names no seat's tool can take).
  - `searched`: a maker whose own words name the string (a command, a
    tool's arguments, a job's command or arguments, the run's paths in them
    blanked first, so an evidence path that holds the string does not make
    it one), and that read nothing of the run but what is accounted for.
  This is the network's evidence link (ADR 0012: a value the cited job's
  own command or arguments name is authored, not derived, whatever its
  output holds; `jobOwnWords`, one helper for both) turned the other way:
  what the run wrote itself is no more a hit against its negatives than it
  is evidence for a fetch.
- **Accounted for, and said among the named hits.** What a maker read is
  accounted for when it is a register, or an object the record names in
  which the same sweep found the same string (the named hit says it
  already). A maker that read only what is accounted for, one object at
  least, and whose words do not name the string, made a named hit again:
  it is said among the named hits with its `origins` (`named_sources`,
  with `reads`). An input is never accounted for: the sweep does not read
  the images, so a derivation of one is the only place its rows show
  (the round-13 export), and its hit holds whatever the record names.
- **What made each name, and when it cannot be told.** A kept output's
  maker is the trace line that kept it (`keptOutputOrigins`, traceOrigin's
  rules for every file in one pass: attributed by the collector to the seat
  whose directory holds it, on the chain), and what it read is what its
  words name (`runPathsIn`, token by token, the run's absolute path and
  `$PWD` taken off). A job's maker is its own record, and what it read is
  its declared inputs; a job that saw everything, or reached the network,
  read what cannot be told. A sealed import is made as the output it
  sealed was (the store journal's seal lines). A maker that names no path,
  names the run's root, a parent, a hidden entry, a path through a
  variable, or a path outside the run leaves its hit standing, and so does
  a line not on the chain, one another seat wrote, and every capture and
  addition. Words, not a parser: a path a command builds while it runs is
  not seen, which is why a maker that names no path is never read as
  having read nothing. The first draft made any maker whose words name the
  string an echo; a search for the string over evidence the record does
  not name is the very miss the sweep is for, and it holds.
- **Where it shows.** The sweep's words say the echoes and each named hit's
  makers, so the ledger's rendering, the review offer (which asks whether
  each is only the run's own words), the report's store sweeps (a record
  whose strings were found only in echoes is listed with the records with
  hits) and the metrics (`sweeps.echoes`) carry them. A line from before has
  no `echoes` and reads as it did. `unexaminedHits` reads each earlier
  record's sweep as the gate does, by its latest line.

Replayed values-free (`swarm.sh replay sd0e59d --resweep`, which reads each
coverage record's recorded sweep again with this checkout's rules and adds
the result as a synthetic line on the copy's chain; nothing is searched
again): of the 20 recorded sweeps' 106 hits, 67 still hold; 26 move to the
named hits, the same bytes as an import the record names; 13 are echoes (8
from the ledger's dump, 3 from the compaction summary, 2 from jobs that
searched for the string over named objects the sweep found it in). The
three `sweep_hits` holds clear, on the sealed imports alone, and the three
questions take the dispositions their answers claim; what still holds the
run is an open lead and route limitations. Whether the seats spend less
time on the sweep is for a paired run.

### Re-reading after a rules change

The run sd0e59d was stopped on the harness before the echoes and resumed
on the one that made them. Its three `sweep_hits` holds (on E-111, E-118
and E-129) did not clear. The gate reads each coverage record's latest
sweep line, every line the run held had been written under the older
identity rule, and nothing read them again: the new rules reached a line
only when a seat recorded its coverage anew, which is the work the fix was
to spare. `replay --resweep` already knew how to read a recorded sweep
under the current rules without searching the bytes again; a live run did
not.

- **A version on each line.** Every coverage record's sweep line names
  the version of the sweep's rules it was written under (`rules`).
  `SWEEP_RULE_CHANGES` lists each version: since when, what changed, and
  whether a line from before it can be read again from what it recorded
  (`bytes`). A line with no version was written before versions were
  recorded and is older than any versioned one. Version 1 is the rules
  above: the same bytes under several names are one object, and echoes
  hold nothing.
- **Read again when the hub starts.** A hub that starts (a kickoff, or a
  resume on a newer harness) reads, in its background, every coverage
  record whose latest line is older than its rules again under them
  (`rereadSweeps`): one line per record, appended on the sweeps' chain
  with the current `rules` and `reread: {from_version, reason: "rules
  changed", of, at, how}` (`from_version` null for a line that recorded
  none, `of` the hash of the line read again). Every such record is read
  again, a corrected one too, since the gate reads an earlier record's
  line for the objects a later record names (`unexaminedHits`). A line
  already under the current rules is left alone, so a second start writes
  nothing.
- **From what the line recorded, or searched again.** Where the change is
  in what a hit is or where it goes, the line's hits are sorted anew as
  `replay --resweep` sorts them (`resplitSweep`): each object by every
  name of its bytes now, named, an echo, said among the named hits, or a
  hit. Nothing is searched, and the line keeps its search's `started_at`
  and `at`, so an entry written after that search still counts as written
  after the sweep that found the hit (`unexaminedHits` reads `at`); the
  re-read's own time is `reread.at`. Where a change needs bytes the line
  did not record (one marked `bytes`, or a line that lacks what a re-read
  needs), the record is searched again for real, within the sweep's budget
  (`SWARM_SWEEP_MAX_BYTES`, `SWARM_SWEEP_MAX_SEC`), and the times are that
  search's (`how: "searched"`).
- **Said.** The trace gets one line, the hub's own (`sweep_reread`:
  `{records, read, searched, lines, holds_cleared, holds_added}`), and the
  board one post: how many records were read again and how, what moved,
  and which of the gate's sweep holds changed, each by its question,
  answer, code and record (`sweepHolds` over each question's standing
  answer, before and after). The sweep's words, in the ledger's rendering,
  the review offer and the report, say a line was read again, from which
  version, and how.
- **Also at the answers check.** `reconcileSweeps`, which the answers check
  and the finish gate run before they read the gate, reads older lines
  again as a step of its own, so a host run with no hub is covered, and a
  replay's evaluation of a copy does the same (`store_sweeps.reread`). The
  step is idempotent: its lines are written under the sweeps' lock, a
  record whose latest line changed meanwhile (another process read it
  again first) is left to that line, and one that could not be read again
  is tried at the next pass.
- **Chains.** The lines are appended: every earlier line stands, the chain
  verifies, and a custody verdict taken before holds the sweeps as a
  prefix. A harness from before reads a re-read line as any other: its
  fields are hashed as they are, and the gate reads the latest line.

Replayed values-free on sd0e59d as of its resume (every chained register
cut at the resume's trace line, before its seats recorded again), 1666851
against this harness (`swarm.sh replay --compare`): under 1666851 questions
2, 5 and 6 hold on `sweep_hits`; under this harness the answers check reads
the 20 recorded sweeps again from what they recorded (in 11 the hits move:
106 hits become 67, the named hits 163 become 189, 13 echoes), the holds on
E-111, E-118 and E-129 clear, and the three questions take the dispositions
their answers claim (partial, bounded negative, not determinable). What
still holds the run is an open lead and route limitations, and the custody
verdict taken at the stop before the resume holds as a prefix.

Not built: a version per rule (a change bumps the one number, and a line
older than it is read again whole); a re-read of the reverse sweep's lines,
whose hits hold nothing by themselves.

## Claim and open-part rows

Added 2026-09-29 (the known-limits plan, item 6). "Partial" was one word
for a whole answer: on s993d40 and c10 complete answers stood partial on
what was a case premise, and a review's parts were free text no answer's
part was named by, so a part the answer never listed could not be seen to
be missing. The brainstorm of 2026-09-29 (L3 and Astra's B2 and C2) merged
the claim rows and the stable part ids into one structure.

- **An answer's rows.** `parts: [{id, part, status: established | open,
  refs, open_by?}]` on an answer to a question: each part the question asks
  as the answer reads its verbatim revision (the one `question_rev` names),
  established on the entries in `refs` (at least one), or open with what
  bounds it in `open_by`: an acquisition ask `R-<n>` (the source that would
  settle it), a route `L-<n>` (the lead that would examine it), or a
  limitation or a coverage record `E-<seq>` (a limitation joins the
  answer's limitations). A premise is never an open part: `open_by: P-<n>`
  is refused, with where the premise goes instead (the answer's `premises`,
  ADR 0011 "Premises"). The rows' entries are citations as the reasoning's
  are. Present-only in the ledger's hashed core, versioned with the entry
  (version 4), so an answer without them hashes as it did; which rows are
  open joins the answer's conclusion fields, and its fingerprint, only when
  it has them.
- **A partial answer names what is open.** A partial answer with no open
  part is refused: "record it established or name what is open", the
  refusal saying the shape. An established answer has no open part
  (refused: record it partial, or establish the part). The negatives and
  the other results may carry rows and are not held to them. Partial stays
  a disposition under every stop policy; the refusal is at record time and
  holds nothing at the finish line, so a run recorded before it reads as
  before.
- **A review's parts by id.** An `answer_review`'s part may name the
  answer's row it weighs (`id`); one the answer does not carry is refused,
  as is an id on a review of an answer that carries no rows. A part the
  question asks that the answer leaves out is a row of the review's own,
  `missing: true`, never established by the answer. A part without an id
  reads as it always did, and round 14's `declared_open` still names the
  entry by which a partial answer declares a part open; a part the answer's
  own row holds open needs neither. Each new field is in the attestation's
  hashed record only when given.
- **What an omitted part does.** On an answer that claims established, a
  missing part caps an established review as a part held not established
  does (strengthCaps): the review is attested best_candidate, and the
  question is held as a best candidate until the answer is recorded again
  with the part, or says why the question does not ask it. On a partial
  answer it caps an established review the same way, and a best candidate
  holds nothing there. Whatever the result, the omission is warned of,
  `part_omitted`, wherever warnings are delivered, until the answer is
  recorded again: it stays visible.
- **Only a part the question asks is open.** On the c10 run s704e4b all
  six answers were partial, and three were complete answers whose open
  parts were mostly what the question does not ask: detail beyond it,
  negatives for example categories the evidence does not show, an
  exhaustiveness no evidence could close, hedges on direction. An open part
  is a part the question asks; the rest are limitations, and the record
  tool, its refusal and the prompt say so (a question that asks for a
  complete set is held to its completeness coverage, not to an open part).
  A review marks a part the answer holds that the question does not ask
  `not_asked: true` (established false, never with `missing`, in the
  attestation's hashed record only when given): it caps nothing, on a
  partial answer or one that claims established. A partial answer whose
  every part its reviews weigh is established, but for those a review marks
  not asked, with at least one review attesting it established, is warned
  (`partial_all_parts_established`, wherever warnings are delivered): record
  it established, with the unasked parts among its limitations. A warning,
  never a hold and never a promotion: the answer stands as its recorder
  recorded it (Astra's "never promote automatically").
- **Where it shows.** The report shows each answer's rows against the
  revision it answers (the question's words beside them), a part a review
  says it leaves out, and a part a review says the question does not ask;
  the console's Questions tab and
  `questions/questions.md` show the rows, the premises the answer cites and
  the omitted parts; `ledger.md` shows both on the answer.

Replayed values-free (`swarm.sh replay --compare <be4e6a3> <this
checkout>`), s5764c4 (Belka, 18 questions), sa2f2f2 and sb1b3c8 read the
same under both harnesses: no difference in any question's disposition,
defects, warnings, readiness or report, their partial answers (without
rows) disposed as before. Every contract fixture recorded before the rows
reads the same under both (tests/contract-fixtures.test.ts). Whether the
rows make fewer complete answers stand partial is for paired runs.

Not built: a recorded result derived from what the reviews hold open (L3-A:
Astra's "never promote automatically" stands until the warnings are shown
insufficient), and a check that the rows cover the question's words (the
review's `missing` is the check).

## What the report shows of an answer's parts

Added 2026-09-30, after the last validation round. Complete answers were
still recorded partial, at medium confidence, and their open parts were
often what the question does not ask. The score did not suffer, but a
reader takes "partial" to mean "not fully known". The owner chose to show
the parts rather than change the label: presentation only, and a metric.

- **Each answer's parts, where it is rendered.** The report's §5 answer
  shows each part established on what it rests on, or open with what bounds
  it, and a review's `not_asked` mark beside the part it marks (a mark that
  names none of the answer's rows is said apart, never dropped); its §2
  chain lists the same parts under its result; its §1 table gives the plain
  line with the answer. The console's question view and
  `questions/questions.md` show the same, from one reading
  (`protocol.ts answerPartsStanding`, `premises.ts partsStanding`), and so
  does the release, whose report is the same render.
- **A partial answer leads with a plain line.** "Asked parts: 3 of 3
  established. Open: 1, which a review marks as not asked." A part is asked
  unless a review marks it not asked; a part a review names missing is asked
  and not established. When every asked part is established (at least one,
  none named missing), the report says so beside the partial label ("every
  part the question asks is established"), in §1 and in the answer. The
  label is the recorder's and is unchanged: nothing is promoted, as above.
- **An answer without parts** (one recorded before them) renders as before.
- **The under-claiming count.** `swarm.sh metrics` counts the standing
  partial answers in scope whose asked parts are all established (`claims`:
  each with its counts; a partial answer without parts named apart and
  counted neither way), and `--compare` marks such an answer on its side,
  flags the question and sets the two runs' counts side by side. The count
  rests on the reviews' marks: a partial answer whose unasked open part no
  review marked is not counted.

Measured values-free on this checkout: s85febc (a calibration run) 0 of 6
partial answers with parts, s704e4b (c10) 0 of 6. Neither run's reviews
marked a part not asked (s704e4b predates the mark), so the count cannot see
the complete answers this section describes there; it counts them from the
runs that review with the mark.

## A part at the limit of the evidence

Added 2026-09-30, after the calibration runs on the claims branch. Complete
answers were still recorded partial, and reviewers never used the
`not_asked` mark, so its warning never fired. Most hedged parts were not
parts the question does not ask. They were limits of the evidence itself:
"whether this was the first exploitation, before the retained logs", "the
payload actually run", "an exhaustive inventory beyond the known entries".
Claude, Fable and Astra reviewed the options, and the owner chose a third
status.

- **A third status.** A part is `established`, `open` (a route or an ask
  could still settle it), or `limited`: the question asks it, and the
  evidence in scope cannot settle it.
  - A limited part names what shows that in `limited_by`: the coverage
    record for its question, or a limitation whose reason is `unavailable`
    or `excluded`.
  - A limitation that was not examined, failed or is partial could still be
    settled. It bounds an open part and never a limited one.
  - A premise is never a limited part.
- **It keeps the answer partial.**
  - A partial answer needs at least one open or limited part.
  - An established answer holds neither, and the refusal says so.
  - The report, the console and the parts line count limited parts apart
    ("Asked parts: 2 of 3 established, 1 at the limit of the evidence"), and
    show what shows each and whether another seat reviewed it.
- **Reviews.** A review weighs a limited part by its id; `at_limit: true`
  agrees that the evidence cannot settle it, and caps nothing. The bound can
  be reviewed as a negative is: a limitation whose reason is unavailable or
  excluded now takes a negative's review. `not_asked` stays, for parts
  outside the question.
- **Measured honestly.** The calibration truth names each question's parts
  and the facts that settle each. `scripts/calibrate.ts` counts:
  - an unnecessary partial: every part the evidence settles is settled in
    the answer's words or its support, never in a limitation;
  - false established;
  - limited parts and their bounds.

  On the claims runs the stricter count agrees with the proxy: 2 of 5 and
  3 of 4.

### Amended the same day: a limited part never lifts the label

As first built, an answer whose parts were all established or limited was
recorded established once another seat reviewed each bound (a cap,
`limit_unreviewed`, until then). The branch's runs measured it:

- **Four calibration runs:** limited was never used. Every open part there
  was bounded by an unavailable limitation or a coverage record and could
  have been limited; the agents chose open. Unnecessary partials did not
  move.
- **Two c10 runs:** limited was used three times.
  - Once fairly, on an exhaustiveness part.
  - Twice on the case's hardest step. In one of these the recorder re-cut
    the question's parts so that the step itself (which file was encrypted,
    and how it was decrypted) was "limited". The answer was recorded
    established at high confidence while its own words said that no
    encrypted file or decryption could be identified.

The bound's review did not catch this: a limit is easy to agree with. The
owner chose honest labels over fewer partials. A limited part now keeps the
answer partial, and the label is never lifted by it. Under-claiming is
accepted for now.

## A locator is not coverage

Added the same day. A decoy value that is literally in the allocated bytes
was attested established high on a verified `reproduced_at` locator, while
the true value sat in file slack, which no seat examined. A locator proves
presence, not truth.

- **A cap on an established attest.** On an established attest of an
  answer to a material question, the hub follows each located object
  (`reproduced_at`) back to the run's input files; a review that locates
  nothing is followed from what the answer's support reaches (see "Decided
  2026-10-31" below): an
  input is its own source, a catalogue member leads to its generation's
  target, and a job's output leads through the job's declared inputs.
- **The condition.** For each such source, a standing coverage record for
  the question must meet all of these:
  - it names the source, or a directory holding it;
  - its `areas` are each `searched` or `not_applicable`, none skipped;
  - its `result_refs` include a job whose declared inputs reach the source.

  Without that record the attest is recorded best_candidate
  (`rival_area_uncovered`), and the reply names the source, what is
  missing, and the fix.
- **The harness never knows what slack is.** It reads the areas a seat
  records (`allocated`, `deleted`, `unallocated`, `slack`, `secondary`),
  the vocabulary the completeness claim already uses, and the jobs' declared
  inputs.
- **What it does not touch.**
  - A located object that traces to no input (a job that read everything,
    or an agent's own file) is not capped.
  - A partial or not-determinable answer is not affected.
- **The review asks the question.** "Could these exact bytes exist if the
  claim were wrong? Which observation would tell them apart, and where
  would a rival value live?"
- **Decided 2026-10-31: the check runs for every review.** The check runs
  whatever metadata the review gives, so a review that supplies less
  verification can no longer pass where one that supplies more is capped.
  With locators it follows the located objects; without, it follows the
  inputs the answer's support reaches: the answer's refs, the refs of the
  entries it cites (and those they cite in turn), and the derivation's
  inputs when it gives one. The same answer gets the same verdict with and
  without locators; the warning `no_locator_or_derivation` stays a warning.
- **Counted.** `swarm.sh metrics` counts the caps and each area's
  `not_applicable` across coverage records, the signs to watch for gaming.
  So does `reversals.partial_after_cap`, which already counts answers
  recorded partial after a cap.

## A question that must be established

Added 2026-10-01, after the Breadcrumbs run (a flag-only challenge under
`--stop operator`, nine seats). The one question's answer was partial on a
reviewed finding, and the part the flag needed was the open part. Under the
one rule above, partial is a disposition. The coordinator's done therefore
ended the run examination-limited after 23 minutes, without the flag. The
operator resumed the run and asked the question again by hand. Nothing let
the goal or the operator say that this question had to be established.

- **What it is.** A question may be required to be established
  (`must_establish` on the question register). For such a question, a
  disposition under the bar is only one of these:
  - an answer the answers check reads as answering it: established on a
    standing finding and not a best candidate, a premise shown not to hold
    on a finding, or a bounded negative under the stronger bar;
  - the operator's acceptance of its limits;
  - its withdrawal.

  Partial, not determinable, a bounded negative short of the stronger bar
  and out of scope still limit the run, as they always did. For this
  question they are no disposition, so the finish line holds the done on
  it. This is one rule under every stop policy: a cap still pauses or stops
  the run and the operator still stops it; under `--stop operator` nothing
  else ends it. Under `cap-pause` and `cap-stop` the agents may still
  abandon a run, as they may abandon any run there (`done` with `abandon:
  true`, a vote of two seats); that end is `abandoned`, never completed or
  examination-limited, but it does end the run with the question open. So
  the requirement binds the agents' done under every policy, and binds them
  fully only under `--stop operator`, where nobody abandons.
- **Who says so.**
  - The goal, which owns the definition of done ([ADR 0002](0002-the-goal-owns-the-definition-of-done.md)):
    a `## Must establish` section naming its questions as it numbers them
    (`- 1`, `- Q-3: why`), or `must_establish:` in its metadata block
    (`[1, 3]`, or a list), which the kickoff writes into that section. The
    seed puts the requirement on each named question's `open` act, present
    only when given, so a goal without it seeds as it always did. A name the
    goal does not number requires nothing, and the kickoff warns of it; so
    does a `must_establish:` key that names nothing. The list's items may be
    indented or not, and a list beside the goal's own section is merged into
    it: neither is dropped quietly, since a bar lower than the one written is
    what this exists to prevent.
  - The operator or an examiner: `question add --must-establish`, and on an
    existing question `question amend Q-n --expect-rev N --must-establish`,
    which makes no new revision.
  - Never an agent, an analyst, a reviewer or an observer: it changes what
    ends the run, as an acceptance does, and they are refused with why. A
    background question is refused it too, since the finish line waits only
    for material questions.
- **The ways out, on the record.** The mechanism that already took a
  question's limits stays the way out. An acceptance (`question accept`,
  bound to the revision and to the answer that stood) disposes a question
  that must be established as it disposes any other: it is the explicit
  release for that answer, and it lapses as acceptances do. The requirement
  itself is released with `question amend Q-n --expect-rev N
  --no-must-establish --why W`; the register keeps who released it, when and
  why, beside who required it, and the chain keeps every act. Nothing else
  releases it: not the stop policy, a review or a vote. A withdrawal of the
  question is a disposition for it, as for any question ([ADR 0011](0011-questions-are-a-register-with-their-askers.md),
  item 9): a person's act on the record, with who and why. The requirement
  does not change who may withdraw: the operator, an examiner, or the person
  who asked it (an analyst, a reviewer or an observer, their own question
  only). So an analyst who withdraws their own question ends its requirement
  with it, on the record; a goal's question is withdrawn only by the operator
  or an examiner, and an agent withdraws none.
- **Where it holds.**
  - The answers check gives such a question no disposition unless its answer
    answers it (`sectionBars` reads the requirement from the register); its
    line says "it must be established, and this is no disposition for it".
    Its `ok` and its defects are unchanged.
  - The finish gate reads that, marks the question `must_establish`, and
    names the requirement first among what blocks it: who required it, how
    its answer stands, and the ways out.
  - The done's refusal says those ways instead of the negative path (plan
    the routes, record the coverage, answer not determinable), which would
    end nothing here.
  - Readiness holds such a question while its standing answer only limits
    the run (`establishesBy`, by what the answer says it is; the rest of the
    bar is the answers check's, and the contract fixtures hold the two
    together), so readiness and the done agree, as they must ([ADR 0015](0015-one-seat-finishes-and-work-is-offered.md)).
- **What the agents are told.** Every header, while it lasts, names each such
  question that is not yet established, who required it, how its answer
  stands, and what ends the run on it. The `questions` view,
  `questions/questions.md`, `question list|show` and the contract (the
  goal's own section, and a sentence in its Questions section) say it too.
- **Why this shape.**
  - Not a stricter stop policy. "Until every question is answered" was the
    ctf12 rule this record replaced: it held every question of a run, so a
    question the evidence cannot answer had only the operator's acceptance
    as an end. Per question keeps the generic bar for the rest.
  - Not a new result or disposition: the bar is the answers check's
    existing "answered" outcome.
  - Not a ledger defect. The requirement is a property of the question, read
    from the register; the answer is not defective. Holding by disposition
    leaves the answers check's defects as they were, so the rule register
    (`docs/rules.md`) does not change.
  - Not a warning on the record ("this answer does not end the run"): the
    header and readiness say it at every delivery.
- **Measured.** Five contract fixtures, under every stop policy:
  `must-establish-partial` (required by the goal; a reviewed partial
  answer), `must-establish-not-determinable` (required by the operator's
  amendment; not determinable on a reviewed coverage record),
  `must-establish-accepted` (required, then accepted),
  `must-establish-released` (required by the goal, then released) and
  `must-establish-established` (required, and established). Replayed
  against main before the change (c61bc2b), the first two are disposed and
  their done proceeds examination-limited under main, and are held under
  this change, readiness holding on `must_establish`. The accepted one ends
  examination-limited under both; only the answers check's own word on its
  partial answer differs. The released and the established ones read the
  same under both, and so does every other contract fixture
  (`scripts/replay-impact.ts c61bc2b`).
- **Not decided here.** The console's question form has no field for it yet
  (the CLI and the goal have). The report does not yet say that a question
  was required or released; `questions/questions.md` and `question show` do.

## A resume refuses a question it cannot admit

Added 2026-10-01, from the same run. The operator resumed it with the
question again and `--as operator`, an id nobody is enrolled under on that
install. The resume admitted its questions only after it had moved the
run's end aside and recorded itself, so the refusal came as a `WARN` after
the run had already gone on, without the question it was resumed for. A
seat noticed and asked.

- **Checked first.** Before anything moves, each question given
  (`--question`, `--questions FILE`) is checked as its admission would check
  it, against the register as it stands: who `--as` names, the words, a
  question the register already holds word for word (`questions-cli.ts add
  --dry-run`, `checkAct`: the commit's own checks, with nothing written,
  signed, supplied or delivered). One it would refuse refuses the resume
  with nothing changed, naming the question and the reason. A broken
  question chain is refused as the admission refuses it. What the dry run
  does not do, the admission does: it takes no lock, writes no seed (it
  reads the goal's, derived) and reconciles nothing an earlier act left
  undone. `direct`, `deliver` and `seed` write by what they are, and refuse
  `--dry-run`.
- **Going on without it is said.** `--skip-refused-questions` leaves such a
  question out and resumes, with a `WARN` naming it and why.
- **Checked again.** The question is admitted after the move, as before;
  the register may have moved in between, and a refusal then is still
  warned of.

## The stop proposal's window

Added 2026-10-01, from the same run. Its stop proposal (item 11 above: 20
committed jobs or 30 minutes with nothing yielded) fired 8 minutes and 20
jobs after the last finding, two minutes before the breakthrough. That was
harmless, since silence approves nothing, but it was noise on work whose
progress comes in jumps. The question was whether the two arms should be
joined (both), or the count scaled with the run.

The answer comes from the recorded runs. They are not in this repository:
they are the owner's own run histories on the machine the runs were made on
(microVM runs from 2026-09-24 to 2026-10-01, the live Breadcrumbs run among
them), and the measure was made on copies of their timing files only (the
budget, the ledger's entries, the question chain, each job's `job.json`,
`done/`, the team), with a one-off script that is not kept either. So the
numbers below can be checked against those histories, not from this tree.
The 45 runs with ten committed jobs or more (5,227 jobs by agents, 4,541
yields: findings, coverage records, answers, dispositions and acceptances),
each segment of a resumed run taken apart, were replayed against the rule
minute by minute and at every committed job:

- The stretches between two yields (each yield counted when it was
  recorded): half lasted 0.2 minutes or less with no job; 99 in 100 lasted
  under 7.2 minutes, and 99 in 100 held 13 jobs or fewer. The longest that
  still ended in a yield ran 22 minutes; the largest held 47 jobs. No stretch
  of 30 minutes or more ended in a yield; 23 stretches of 20 jobs or more
  did, every one within 30 minutes.
- The rule as it was (20 jobs or 30 minutes) proposed 27 times in 10 runs.
  26 of those came on the job count, 20 jobs in one to eight minutes, and
  every one of them was followed by a yield, 25 within ten minutes. The
  27th came on the minutes, in a run whose seats had run no job for 30
  minutes; nothing yielded again, and the operator stopped it a minute
  later. That "nothing yielded again" is partly the operator's doing: the
  stop came before the run could show whether it would recover, so this
  one stall is a weak positive. The case for the change rests on the 26
  proposals that the work went on to answer, not on it.
- Both arms (20 jobs and 30 minutes) would have proposed nothing at all,
  and would have missed that stall, which had no job. A count scaled to the
  seats (five a seat, 50 at ten seats) proposed only the stall, but by a
  margin of three jobs over the largest stretch that still yielded. The
  minutes alone proposed only the stall.

So the minutes decide: a stop is proposed after `SWARM_YIELD_MINUTES` (30)
with nothing yielded. The job count proposes nothing by default;
`SWARM_YIELD_JOBS=N` puts it back beside the minutes for an operator who
wants it. Everything else stands: the proposal is the operator's request,
never an agent's vote, never a stop by itself, and silence approves nothing.
The count of jobs is still said in the proposal. This is a measure of what
the rule would have done on recorded histories; whether 30 minutes is the
right length for runs much larger than these is for later runs to show.

## What the operator is told under `--stop operator`

Added 2026-10-01, from the same run, before it is run again. Under
`--stop operator` every cap is advisory and says nothing: the run spent 790 M
tokens with nothing told to anyone. Three things for the rerun's protocol
(its first tranche of tokens, its stop rules), each telling and none
stopping:

- **Token marks.** `--token-alert N[,M…]` names marks in tokens; as the run
  crosses each, the operator is told once, on the board, the trace
  (`token_alert`), the console's Budget tab and the notify hook
  (`token_alert`, the mark and the count). The claim is a file per mark
  (`traces/token-alerts/<mark>`, created exclusively), so the hub of a VM run
  and the watchdog of a host run never tell one twice, across restarts and
  resumes. Advisory under every stop policy: the decision stays the
  operator's, as with the stop proposal.
- **The operator, named before the run.** The first resume's question was
  refused because `--as operator` named nobody enrolled. `--operator ID`
  names an enrolled examiner or analyst at kickoff (refused otherwise,
  before anything is written) and records them; on the run's acts `--as
  operator` names them. A run that names none keeps the old reading (a
  person enrolled under the id `operator`, or the refusal above).
- **The model asked for, and the model that answered.** The record keeps the
  model ids asked for and the date (`model_identity`), and the kickoff warns
  of an id that names no dated model (`latest`). When a provider says
  another model answered a seat, the seat's harness says so: an alias
  resolved to one of its dated ids is put on the trace (`model_reported`,
  resolved); any other model is a substitution, on the trace, the board and,
  through the hub, the notify hook (`model_substitution`). It is the
  operator's to act on; for a run meant to be compared it is a stop rule.
  What a provider does not report (the Responses APIs, Codex's included,
  carry no answering model in Pi's message) is not compared, and the record
  says only what was asked.

## Consequences

- Every existing goal and run keeps working: an answer without `result`
  reads as before, `inconclusive` is `not_determinable`, a budget without
  `stop_policy` is `cap-stop`, `--until-solved` keeps its meaning, and a
  ledger version 4 core is unchanged when the new fields are absent.
- A run no longer ends at a cap by default. An operator who wants the old
  behaviour for an unattended run says `--stop cap-stop`; a run that pauses
  overnight waits, holding nothing but its disk.
- A negative in a report now carries its scope and its reviewer, or says it
  has none. "It did not happen" needs the evidence for saying so.
- A case can grow without losing its custody: further questions after a
  stop are the same run's, and the releases say which chains each one bound.
- A negative over a source whose pack parses it whole waits only while
  that parse is under way, and only when it claims absence or complete
  coverage; every other says it was weighed without it. A pack that
  declares nothing changes nothing.
- Evidence added late is searched at once for what the standing coverage
  looked for, and an answer it stales stands again only on an entry that
  says how the evidence bears on it. A citation of the import no longer
  clears it; a hit never holds by itself.
- A partial answer now says which part is open and what bounds it, and a
  review can say which part of the question an answer leaves out; an
  answer recorded before the rows reads as it did.
- Not decided here: the acquisition lane and notifications as sealed
  material (Phase 1b), the full offer protocol and the reviewer's query
  (Phase 2), the report's per-question chains (Phase 3), and the mediated
  network (Phase 4). The resume relaunches the team the way a start does;
  what a real VM or Herdr relaunch does beyond the kickoff is exercised by
  the kickoff's own tests, not by one of its own.
