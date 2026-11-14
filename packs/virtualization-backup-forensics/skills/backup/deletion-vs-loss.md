---
id: backup/deletion-vs-loss
title: Deletion attempted, reported, observed, verified
when: A backup, snapshot or restore point may have been deleted, pruned, expired or overwritten.
needs: [evidence/coverage]
card: backup_audit_normalise gives only a deletion's requested and reported states; observed and verified loss need listings and restore tests it does not produce. A reported success is a claim. Does not show: intent, the human, or that recovery is impossible.
tools: [backup_audit_normalise]
requires_host: []
mentions: [vss_stores]
---

Use when the claim is that recovery data was destroyed, or that it was not. Not for the catalogue, repository and retention comparison (`backup/catalogues-and-retention`) or Windows shadow copies (the Windows pack's `vss_stores`, if loaded).

Four states, each with its own evidence; one does not stand in for the next.

| State | Evidence that shows it | Evidence that does not |
|---|---|---|
| **Requested** | an audit or task record of a delete, prune, expire or retention change, with account and time | a command seen in a guest's history; a job's name |
| **Reported** | the product's own result (ok, warning, error) for that operation | a missing next job |
| **Observed** | a catalogue or inventory listing, taken after, without the object | a listing taken before; an empty search with no stated coverage |
| **Verified loss** | an authoritative storage listing without the bytes, or a restore test failing for lack of data | a catalogue entry gone; a repository path unreadable |

1. **Build one row per object and per state.** `backup_audit_normalise` (readers: `backup/product-presets`) gives the requested and reported rows with their categories (`snapshot_delete`, `retention_prune`, `retention_gc`, `retention_remove`, `vm_delete`, `disk_delete`); the observed and verified rows need listings and restore tests, which this pack does not produce.
2. **A reported success is not a loss;** it is the product's claim. A failed deletion is not "nothing happened": a partial removal can leave a chain with a hole (`snapshots/chain-integrity`).
3. **A catalogue entry removed is not the bytes removed.** Many systems keep data until a later cleanup, or soft-deleted. Ask what this version does, and read the repository.
4. **Absence is bounded** (`evidence/coverage`): the source, the period, what the history keeps; rotating task history can lose the very request.
5. **Retention explains a deletion only with the setting.** Match its time and account to the policy; an off-schedule removal, or one by an interactive account, is a lead, not a finding.
6. **Name the claim that is safe.** "Deletion of X was requested by account A at T (record R); the product reported success; a listing at T2 no longer shows X; the repository was not listed" is what the evidence can carry.

**Shows.** Which of the four states each object has evidence for. **Does not show.** Intent, the human, or that recovery is impossible: check surviving copies (`recovery/survivability`).
**Record.** Per object: each state, its source and locator, its time and clock, and what is unverified.
**Sensitive output.** Run `backup_audit_normalise` as a job with `secret_output: true`; cite an event's locator, not its message. Names show only if plain, else `<withheld N characters: reason>`; free text has secrets withheld; a short plain password passes unseen.
