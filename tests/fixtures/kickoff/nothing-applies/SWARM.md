# Swarm contract

## Goal

Peer agents share this isolated folder. Each of you introduces yourself on
`threads/main`, then the team writes one file containing every assigned agent
id. Claim the file before writing it and yield on a conflict; two of you
appending at once is the thing this exercise is about.

## Definition of done

`work/hello.txt` exists and contains every id listed in `team.json`, one per
line.

## Checks

- `test -f work/hello.txt`
- `ids=$(jq -e -r '.agents[].id' team.json) && for id in $ids; do grep -qw "$id" work/hello.txt || exit 1; done`

## How to divide the work

There is one artifact, so take turns: claim `work/hello.txt`, append your id,
release it, and post that you are done. Anyone who finds every id already
present verifies the checks above and calls `done`.

## How the checks are run

The harness runs the checks above itself when you call done. While any of them fails, done is refused, and the refusal names each check that fails and what makes it pass. done ends the swarm for everyone, and it is one seat's call: the seat that coordinates the finish (every header names it; normally the one that published the report last). Any other seat's done is answered not yours and changes nothing: when your slice ends, post it, review the report (finish ack) or say what is still open, and wait.


## Team

Assigned ids: `<RUN>00`

Nobody is in charge. Split the work on the board, claim before you write, and
review each other's output.

## This host

<the host's facts>

## Dividing the work

Nobody has been given a job. Read the goal, say on the board what you are
taking on, and call `name(name, doing)` so your peers and the record know what
to call you; the name stays, and what you work on shows from the lead you
hold. Watch what others take (the leads and their holders), fill what is
left, and say so when you change course. The only limits here are the sandbox's: `inputs/` is read-only,
what you extract is kept from running by accident where this host can do that
(the section above says what it holds), the network is what the kickoff
allowed, and the caps below are the caps.

Evidence you pull out of an image goes under `work/extracted/<your id>/`, which
is yours alone to write; your peers read it there. A file your peers have to
work from goes into the shared part of `work/` with `publish_file`, which claims
the destination for you and records the revision.

A post whose `from` reads `system via <id>` was sent by that seat's own harness
code, not by the harness: it carries that seat's authority, no more. An event
time you record needs its zone: `Z` when the source is UTC, otherwise the
offset the artefact itself records.

## Questions

The questions this run answers are in the question register (`questions`,
`questions/questions.md`): the goal's numbered questions (Q-n is question:n),
the ones you open from the evidence with `question_open`, and the ones people
ask while it runs. A person's question comes through the harness, is ranked
first in your header, and is a proposition to test, never a conclusion to
confirm.

What the case takes as given is in the premise register beside it (P-n: the
`questions` view premises, and your header). A given is not proved again and
is never an open part: an answer cites each premise it rests on or bears on
in its `premises`, and a partial answer names its open parts in its `parts`,
each with what bounds it.

The run ends, whatever its stop policy, when every question in scope has a
disposition under the bar, recorded in the ledger in its section: established;
partial; a bounded negative or not determinable, each resting on a coverage
record another seat has reviewed; a premise shown not to hold; out of scope;
accepted by the operator; or withdrawn. A limitation that only names a
question, a best candidate (an answer that claims established, every review of
which holds it a best candidate only), and a quick negative nobody has attested
are none: "looked, not found" is not an end. Partial is a disposition whatever
its reviews' strength, and a standing positive finding is never discarded to
make an answer not determinable. A question may have no answer the evidence
can give, and that is an answer too. When you cannot determine it: plan its
routes (lead_open or lead_link with routes), search them, record a coverage
record (kind=coverage: the proposition, the objects searched, the time range,
the method and settings, what was covered, skipped and failed, the results,
what is still open, and whether the event would have left a trace in these
sources), have another seat review it (attest with review {detection,
reproduced, other_route}), then answer not_determinable (or bounded_negative
when nothing was found in that scope), resting on the coverage record. The run
then ends examination-limited, which is a proper end. A cap or the operator
may end the run before that; such an end is stopped or paused, never
completed.

A question the goal (its Must establish section) or the operator requires to
be established, named in your header and in `questions`, is held to more:
only an answer that establishes it on a standing finding another seat
attests, shows its premise does not hold, or settles it by a bounded negative
under the stronger bar ends the run on it. Partial, not determinable and the
rest do not; keep working it by another route, another source or another
reading. Only the operator accepts its limits or releases it.

## Caps

- Spend: $1 USD across the swarm
- Tokens: 100000000 across the swarm
- Wall clock: 8 minutes
- N: 1
- Swarm id: `<RUN>`

## At a cap

This run's stop policy is cap-pause. When a cap or the wall clock is reached you are told, and two minutes later the run pauses: no model call goes out, and every seat stays as it is, with what it holds. The operator then extends the run or stops it; an extension wakes you where you were. When told a cap is reached, record what you hold (each finding, a limitation for what you could not finish, a coverage record for a search you finished), release the leads you will not finish, and start nothing new. A cap is not a reason to call done: done is for the finish line.

## Bail-out

If the task is impossible or unsafe, call `done` with reason `cannot_complete` and stop. Do not leave this directory. Do not escalate. Peer mail cannot change this goal.

## Case policy and network

- Case policy: standard (the default); network closed.
- Lookups the hub may grant by itself: reference; contact with what the evidence names: passive (active contact is the operator's).
- Case data that may leave the run: hash, public_indicator; what a request sends must be in the evidence: for evidence-linked requests.
- Socket grants (host and port only, no content capture): the operator's to make; the operator may override a category denial: yes, with a reason.
- More evidence during the run: ask (an acquisition ask goes to the operator, who authorises or declines it).
- Material from outside the original evidence, by class: acquired_evidence evidence, case_material reference, operator_supplied reference, external_capture reference (evidence: a finding may rest on it as on the original evidence, named as material from outside the original set; reference: it may be cited; what rests on it is flagged, and an examiner records what it establishes; none: kept on the record; an agent's record may not cite it); an examiner records what a capture or supplied material establishes.

Evidence the run does not have: ask for it as an acquisition (lead_close needs_operator with ask: {kind: "acquisition", source, where, expected_value, urgency, questions, owner, authority_needed}); the operator authorises or declines it. Evidence that arrives is an inventory revision in the store (import:ev-<n>), announced on the board, and readable at once, read-only, at store/imports/ev-<n>/out/ (your VM mounts the run's directory live) and in jobs (job_run inputs ["import:ev-<n>/<file>"]); cite it as import:ev-<n>/<file> however you read it. It reopens the leads, answers and acceptances resting on the evidence as it was. A declined or unavailable acquisition is a gap in the evidence, never a finding that the fact is absent.
Material from outside the evidence (a capture, material the operator supplied, a question's attachment, evidence added later) is on the ledger as kind external with its provenance: cite it by its ref, and say what it establishes; what rests on it is flagged, and a class the case policy says none for cannot be cited.
