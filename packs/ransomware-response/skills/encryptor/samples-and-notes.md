---
id: encryptor/samples-and-notes
title: Recovered samples, tails and note placement
when: You hold a recovered binary or script, repeated tails, or note placement.
needs: []
tools: [encrypted_survey, ransom_note_scan, encryption_extent, ransomware_family_match]
requires_host: [yara]
card: Read and hash recovered code; never run it. A yara match is a classification lead, not proof of execution or attribution. encryption_extent ({"policy": "sampling", "census": "<census>"}): high_entropy_fraction is a share of the inspected bytes, not a percentage encrypted. ransom_note_scan (a job with secret_output: true) shows where a note was written, not which directories were encrypted; a tail repeated in encrypted_survey is a coincidence until checked against the format and other files. Does not show: who ran what.
---

Use only if you hold a recovered binary or script, or read tails and note placement. Not for the execution chain (`encryptor/traces`).

**Samples and file effects.** Read and hash recovered code; never run it. The pack ships a
dated snapshot of note-text rules and family features for a few families, used by
`ransomware_family_match`; it ships no rule for a sample's code. If `yara` is installed and
the case supplies a ruleset, record the engine version, the ruleset's source, revision and
hash, the rule names and the match locations. A match is a classification lead, not proof
of execution or attribution.

`encrypted_survey` names candidates and samples a few tails; its answer says what it
read and did not (`status`, `status_basis`, `coverage`). `ransom_note_scan` says where note files
sit, by name and content. Where a note sits shows where something wrote a note, not
which directories were encrypted. Check a repeated tail against the file's own
format, against independent files and against supported family research before it
means more than a coincidence. Note placement, renaming and encryption can each
occur without the others.

`encryption_extent` measures where in a named file, or in the survey's candidates
given by their census, windows read as high entropy. You declare a policy
(`sampling` or `full`); it names the bytes it did not inspect and checks the
head and the end of the file against its format. Its `high_entropy_fraction` is a
share of the inspected bytes, not a percentage encrypted: compressed formats
read high too, and a pattern finer than its window is not located.

**Sensitive output.** `ransom_note_scan` reaches values that can carry access: run
it as a job with `secret_output: true`, cite a value by note id and offset, and never
write one, or a hash of one, into the ledger or the report.

**Does not show.** A note's place does not show an encrypted directory; a rule
match does not show who ran what.

Record: the sample's hash and source, the engine and ruleset (source, revision, hash), rule names and match locations, the survey's `status`, `status_basis` and `coverage`, the extent's policy and its uninspected ranges.
