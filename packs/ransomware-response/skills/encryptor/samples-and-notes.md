---
id: encryptor/samples-and-notes
title: Recovered samples, tails and note placement
when: You hold a recovered binary or script, repeated tails, or note placement.
needs: []
tools: [encrypted_survey, ransom_note_scan]
requires_host: [yara]
---

Use only if you hold a recovered binary or script, or read tails and note placement. Not for the execution chain (`encryptor/traces`).

**Samples and file effects.** Read and hash recovered code; never run it. No rules
ship with this pack: if `yara` is installed and the case supplies a ruleset, record
the engine version, the ruleset's source, revision and hash, the rule names and the
match locations. A match is a classification lead, not proof of execution or
attribution.

`encrypted_survey` names candidates and samples a few tails; its answer says what it
read and did not (`status`, `status_basis`, `coverage`). `ransom_note_scan` says where note files
sit, by name and content. Where a note sits shows where something wrote a note, not
which directories were encrypted. Check a repeated tail against the file's own
format, against independent files and against supported family research before it
means more than a coincidence. Note placement, renaming and encryption can each
occur without the others.

**Sensitive output.** `ransom_note_scan` reaches values that can carry access: run
it as a job with `secret_output: true`, cite a value by note id and offset, and never
write one, or a hash of one, into the ledger or the report.

**Does not show.** A note's place does not show an encrypted directory; a rule
match does not show who ran what.

Record: the sample's hash and source, the engine and ruleset (source, revision, hash), rule names and match locations, the survey's `status`, `status_basis` and `coverage`.
