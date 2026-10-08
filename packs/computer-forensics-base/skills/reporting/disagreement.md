---
id: reporting/disagreement
title: Correct the evidence record and every dependent conclusion
when: A finding is disputed, or new evidence changes a reviewed result.
needs: [reporting/citations]
tools: []
requires_host: []
---

Disagreement is how a case gets better, and it has to leave a record that outlives
the conversation. This is a method skill and names no tool: the acts below are the
harness's.

**Another seat's entry looks wrong.** Use `dispute(seq, why, refs)`: say which
observation or inference fails, cite the contrary source in `refs`, and name the
check that tells the alternatives apart. Post on the board when peers need to
coordinate; a post does not replace the dispute. A `veto` stops a proposed action
(a write, a command), not a claim.

**Your own entry was wrong.** Record the corrected one with
`record(..., supersedes=<seq>)` and say why it changed. Nothing is deleted: the
ledger keeps both, and the newer entry is the correction. Others have already cited
you, so tell them which entry to use. Take your own dispute back with
`withdraw: true` when you are satisfied.

**Review source-first.** Read the question and the original sources before the
proposed conclusion, re-derive the decisive observation, test the strongest rival
explanation, and say what you reproduced and what you only read. Agreement among
agents that used the same parser on the same source is not independent
corroboration, and neither is a second wrapper over the same library. A material
disagreement you cannot resolve is preserved, with its effect on confidence.

**A correction after sign-off.** When a conclusion changes after sign-off, the
board can carry the right answer while the report keeps the wrong one: a board
post and a reopened report resolve nothing by themselves. Trace the correction through the entries, the
indicators, the coverage records, the answers, the timeline and the report sections
that rest on it, re-record the conclusions that changed on standing evidence, and
get the reviews the changed result needs: an answer resting on an entry that was
superseded or disputed stops standing until it is recorded again. The coordinator
republishes the report, calls `finish` prepare and resolves each late result or
objection with the current generation and digest; reviewers acknowledge only the
changed sections. Reading a late post, or publishing the report again, does not
by itself resolve an objection.

Before you sign off, read the board from your last post to now.
