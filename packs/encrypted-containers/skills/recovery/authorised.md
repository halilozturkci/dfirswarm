---
id: recovery/authorised
title: Authorising and running password_recover
when: The case contract authorises an attempt to recover a password from evidence or an extracted hash.
needs: []
tools: [password_recover]
requires_host: [john]
---

Use when the case contract authorises an attempt to recover a password and you decide whether and how to run it. Not for locating key material the case may already have (`keys/where-they-hide`).

Record before running anything: the question that needs the password, the authority for attempting recovery (the case contract's own wording, not inferred from having the device), the basis (why an attempt is proportionate here), the scope (which file or hash, which candidate list, for how long), the approved method, and the stopping condition (a time budget, a candidate list exhausted, or a result found).

`password_recover` is this pack's one password-recovery route: a job run with `secret_output: true` extracts a hash with the matching *2john helper, or takes one from another sealed job by reference, then runs john against a case-supplied candidate list. It never runs outside a job the harness ran that way, and never takes a candidate as a value on a command line or in its answer: the list is a file, named once in the call, never read into the conversation. Choose the candidate list and the optional rule set from the case's own record of likely passwords; each run is its own authorised attempt, under its own recorded basis, not a general word list tried "to see". The answer is `complete` only when nothing was left running: a process john or the helper left behind, or a host where that cannot be ruled out, makes it `partial` (`program_group` says which).

**Does not show.** That a password used elsewhere is this one; that an attempt which found nothing means no password exists, or that trying again under a fresh basis is out of scope; what john's pot file holds beyond the count `password_recover` reports.

**Sensitive output.** Every job runs `secret_output: true`. A recovered password lives only in the sealed pot file the tool's answer names; cite it by that reference, never by value. Record the question, the authority, the basis, the scope, the method and the sealed reference: never a password, a fragment of one, a hash, a salt or a length. Hand a recovered value to the operator through the channel the case contract names.
