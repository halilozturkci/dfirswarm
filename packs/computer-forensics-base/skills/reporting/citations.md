---
id: reporting/citations
title: Connect each answer to inspectable evidence and its limits
when: Recording a material claim, reviewing an answer, or preparing the report.
needs: [timeline/build]
tools: []
requires_host: []
---

This is a method skill and names no tool: the ledger, the job references and the
review acts are the harness's.

A claim in the report resolves to a source object and an inspectable observation.
Record the sealed object it rests on (`input:<path>`, `job:<id>/<path>`,
`member:<gen>#<n>`), the artefact's own locator (a path with its inode and
attribute, a registry key with its last-write time, an event record id with its
channel, an offset in a blob), the field or bytes that matter, the tool, its
version and its settings, and how the observation supports the claim. A command
alone names an intended method, and a digest alone identifies bytes: neither
replaces the observation or its interpretation. A sentence with none of these is
an opinion and a reviewer will treat it as one.

Answer each question against its current revision, from standing ledger entries:
the result, which parts are established and which are open, the reasoning, the
confidence and why, the contrary evidence, the limitations and what would change
the answer. Keep `partial`, `bounded_negative`, `not_determinable`,
`out_of_scope` and `premise_not_supported` where they apply: a report that answers
six of eight questions and names the two it could not survives review, and one
that fills all eight with guesses does not. The headings the goal names organise
the report and the finish line reads them; a heading that is present does not
establish an answer.

Keep observation, inference and conclusion apart, and state the observation at the
level the artefact supports: "the cited System event record reports a service
creation at its recorded timestamp", not "the service was created at 21:19:22".
Who did it, the true wall-clock time, whether the operation succeeded and what
caused it each need their own support. An account is not a person, presence is not
execution, a destination string is not a completed transfer, and a catalogue
listing says a file exists and not what is in it: open the file before you cite it.

A negative is bounded. Word it "no evidence of X was found in these objects over
this period", never "X did not happen". Name what was searched, the time range,
the methods and settings, what failed or was excluded and whether the event would
have left a trace in those sources, with the coverage record and an independent
review. A collection that was missing or a parser that failed is not evidence that
an event did not occur. Qualify any reliance on the output of a partial or failed
job.

Secrets stay out of report prose and ordinary ledger entries. Say where one is,
its type, its length and what it grants, cite the sealed reference, and write
neither the value nor a hash of it.
