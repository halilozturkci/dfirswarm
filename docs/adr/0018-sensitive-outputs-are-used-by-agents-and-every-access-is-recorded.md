# Sensitive outputs are used by agents, and every access is recorded

The sensitivity mark on a job's output protects what flows out of the run:
the board, the ledger, the report, the package, the trace's command lines
and the network. It never protected the output from the agents of the run,
and it will not start to. An investigation needs its agents to use a cracked
password to open the container it belongs to, to hand a recovered key to the
next job, to read a values file the tool wrote for exactly that. So a
sensitive output stays readable by every seat and every later job, nothing
is held back from them, and the harness records each access it can see, so
that the report can say who read what, and says plainly how much it cannot
see.

Status: accepted, 2026-10-21. Decided by the owner. It adds to decisions 6
and 7 of [ADR 0016](0016-the-report-follows-each-question-and-the-outputs-carry-their-sensitivity.md)
and contradicts neither: marking, derivation, the ledger's `sensitive`, the
sensitive words of the board rules and the package's redaction stay exactly
as they are. What changes is the reason given for the mechanism and what is
built on it. The record is built in the changes that follow this one; this
page is the decision they rest on.

## Context

- The mark comes from `secret_output` (an agent's flag, or a tool's
  manifest) and spreads: a job that read a sensitive output is derived, an
  entry citing one is recorded sensitive, a package made with `--redact`
  withholds the files and scans for the words. Every one of those protects a
  place the content could travel to. The harness marks without reading the
  bytes, and the worker prompt says that a job's outputs are where "every
  agent and every later job reads it".
- One passage of the pack documentation went the other way. It asked a tool
  that writes secret values to a file to offer no filter, no expression, no
  predictable size, time or order over them, because with text you cannot see
  each call is a bit of every row; and, in the same passage, it said that the
  sandbox's `store/` is mounted read-only in an agent's VM, so an agent that
  opens the file reads every row. The first half assumed the file could not be
  opened. The second half said it could. Nothing in the harness has ever
  prevented the opening, and nothing was meant to.
- A secret that is found is meant to be used. A key found in a case opens
  the container it was kept for; a password a job cracked unlocks the
  archive it was cracked from. A mechanism that kept the value from the
  agents would stop the work it exists to serve, and the alternative (a
  second, private area of the store, a resolver, a refusal at submission)
  would have to be paid for in every path that reads the store.
- What the value does once an agent has read it is not new in kind. The
  model sees the output of every tool the agent runs, file contents included,
  and that is evidence content sent to the provider's hosts
  ([data protection](../data-protection.md)); the summary model receives the
  whole context; the trace keeps what the model received. What is new is that
  a value the run marked sensitive now takes those routes, so the marking and
  the redaction carry the weight, and the run needs to know who read what.

## Decision

1. **The mark protects outflow, not the agent.** Marking, derivation, the
   ledger's `sensitive`, the board's rules on names, labels and questions,
   the report, the package and the network adapters are kept as they are.
   Nothing is withheld from a seat or a job on the way in: a sensitive output
   is read where it is sealed, in `store/jobs/<id>/out/`, by anyone with the
   store, whole.
2. **Derived jobs stay visible.** A job made from a sensitive output is
   marked sensitive and listed, named and counted, like any other job. The
   mark is not a reason to hide the job from the board, the console or the
   report.
3. **The operator's console shows sensitive content.** The operator is the
   owner of the run and sees what the run holds. Each time the console opens
   a sensitive file, that is recorded.
4. **A broad-scope job that names a sensitive path runs.** A job with no
   declared scope whose command, arguments, source or targets name a
   sensitive output is not refused. The dependency is declared on the agent's
   behalf and recorded with the way the harness found it (declared, by
   digest, by generation, by alias, named in the text, same bytes), the job's
   output is marked sensitive, and the answer says so in one sentence. A job
   with no declared scope that names nothing records which sensitive outputs
   existed when it started, which is what it could have read and not what it
   did.
5. **The `tool-output/` mirror is the rule, and it holds the values.** An
   agent's whole tool outputs are kept under `tool-output/` and named, as
   they are now; a page of a sensitive job's output is kept the same way and
   is not made into a stub. The sandbox's `store/` and `tool-output/` mounts
   stay read-only and open. Every read of a sensitive output that the harness
   sees is logged.
6. **No echo detection and no stdout holding.** The harness does not search
   an agent's output, a job's stdout or a post for a value it has seen, and it
   does not hold a job's standard output back from the agent that asked for
   it. Sensitivity follows the objects a job was given, not what its text
   looks like. A job that is known to have seen a sensitive output is marked
   in the report, and that is all the harness claims.
7. **The agent is told once.** When a seat reads a sensitive output the
   agent gets a single sentence: that the output is sensitive, that the read
   is recorded, that the value does not belong in a post, the ledger or a
   command line, and that it goes to another job as an `input`. It informs,
   and does not block, as the note on code written in evidence already does.
8. **The provider's exposure is accepted, and the report names it.** A value
   an agent reads is sent to the provider of its model, to the summary model
   when its context is summarised, and is kept in the trace and in the
   seat's session. For each seat that read a sensitive output the report
   gives the model and the host it was served from, which the report already
   knows. A case that cannot let a value reach a cloud model runs with
   `--local-only`; no separate switch is added.
9. **`--redact` removes what the record marks.** The access record says
   which lines of the trace carry sensitive content (a read's result, the
   page a tool output was kept as). A package made with `--redact` replaces
   each of those lines with a hash of the line, and the chain checks as it
   does for a redacted line today. This closes a gap the word scan cannot:
   a sensitive file over 256 bytes, printed by a `cat`, sits in the trace
   as it was. A package made without `--redact` changes nothing, as now;
   `HYGIENE.json` counts the trace lines that carry sensitive content and
   says to hand the package over with `--redact`. A line the record marks as
   "maybe" or "text" is replaced as well: redacting too much costs a line,
   and redacting too little costs a value.
10. **The record is a lower bound, and the report says so in a fixed
    sentence.** What the harness sees is what an agent's own tool call names:
    a path the read tools are given, a path or sensitive job id in a command
    line, a blob digest, a root that a command walks, a page of a job's output
    that a tool returns, and what the harness itself stored about a job's
    inputs. It does not see a path computed by a program, a read through a
    copy that was not a recorded page, or a program that opens a file by a name
    the command does not hold. The report's section ends with: "Reads through
    a computed path, through a copy that was not a recorded page, or by a
    program that opened it by a name the command does not hold are not seen.
    This list is a lower bound." Each row carries how sure the harness is
    (certain, a named path, text that names it, or a possible reach), and
    custody states the same limit. Kernel-level observation of every read is
    not part of this decision; it can be added for the cases that need it.
11. **Derived stays sensitive.** The output of a job that read a sensitive
    output is sensitive, and so on through a chain, also when the key opens a
    container and the content of the container is not the key. The harness
    cannot tell a key's use from a copy of it without knowing a tool, and it
    knows none. No switch is added now; the first report that shows it too
    broad is the occasion to decide one.
12. **Tools keep the value in a marked file, and the reason is the file.**
    The contract of a tool that can reach secret material does not change:
    the value is written only in a job run as secret output, only to a file
    under `$OUT`, never to the answer, an error, a path or a field name.
    The reason is that a value in a marked file is covered by everything
    above, and a value printed in an answer is not: it goes into a post, the
    ledger or the trace's command lines unmarked. It is not that an agent must
    not open the file. The measures tools took against a bit of a hidden value
    leaking through an answer's size, timing or order stay where they are
    built, are not extended, and are not a boundary.

## What the record is made of

There is no new register. The record is read from what the run already
writes, each in a chain that custody seals:

- **The trace.** The hub adds a line of its own for a seat's read of a
  sensitive output, from the tool calls that pass through it, and for a page
  of a job's output that an API call returned. A line points to the tool row
  it was made from and carries the job, the part and the path, never the
  value, a digest of the value or a range of its bytes.
- **The store's journal.** A job's start records the dependencies the
  harness added on the agent's behalf and the sensitive outputs that existed
  when it started with no declared scope; a job's commit records why it is
  sensitive and from which outputs.
- **The ledger.** An entry that cites a sensitive output is recorded
  sensitive, as now; the citation is the agent's own claim.
- **The operator's record.** The console's views of sensitive files.

One reader joins them for the report, custody, the console, a command line
and the package. It keeps three kinds of evidence apart, because they are
three different things: a link the harness verified (a declared or added
input), a read the harness observed (a path or command that names the
output), and what an agent says it did (a ledger entry). "Opened the
container" is only ever the third. A tool, a format or a program is named
nowhere in it.

## Consequences

- An agent can use a recovered secret, and the work that needed it is no
  longer blocked by the harness. The price is that the value is in the
  model's context and in the trace, which the accepted exposure and the
  `--redact` lines above are for.
- The report says, for each sensitive root, who read it, how sure the
  harness is, which jobs used it, which entries cite it and what the console
  showed, with the model and host of each reading seat, and the sentence that
  the list is a lower bound. It does not say that a value was copied, echoed
  or leaked: the harness does not look.
- A reviewer of a package finds a count of trace lines with sensitive
  content in `HYGIENE.json` when `--redact` was not used, and none of them
  in a package made with it.
- The rules that decide which paths and commands count are versioned in one
  place. When they change, custody keeps the earlier lines as written and
  derives the record again by the new rules, and says that the rules changed.
- Packs and tools written for the earlier assumption are not rebuilt. The
  documentation of a tool says what it keeps out of its answer and why; it
  no longer promises that the file cannot be opened.
- Not decided here: observing every read at the kernel, a switch that
  excludes a key's use from derivation, a rule that refuses a cloud model for
  a case that holds secrets.
