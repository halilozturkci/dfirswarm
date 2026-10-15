---
id: backup/deletion-vs-loss
title: Deletion attempted, reported, observed, verified
when: A backup, snapshot or restore point may have been deleted, pruned, expired or overwritten.
needs: [evidence/coverage]
tools: [backup_audit_normalise]
requires_host: []
mentions: [vss_stores]
---

Use when the claim is that recovery data was destroyed, or that it was not. Not for the catalogue/repository/retention comparison itself (`backup/catalogues-and-retention`) or for shadow copies on Windows (the Windows pack's `vss_stores`, if loaded).

Four states, each needing its own evidence. Do not let one stand in for the next.

| State | Evidence that shows it | Evidence that does not |
|---|---|---|
| **Requested** | an audit or task record of a delete, prune, expire or retention change, with account and time | a command seen in a guest's history; a job's name |
| **Reported** | the product's own result (ok, warning, error) for that operation | a missing next job |
| **Observed** | a catalogue or inventory listing, taken after, without the object | a listing taken before; an empty search with no stated coverage |
| **Verified loss** | an authoritative listing of the storage shows the bytes absent, or a restore test of the point fails for lack of data | a catalogue entry gone; a repository path unreadable |

1. **Build one row per object and per state.** `backup_audit_normalise` gives the requested and reported rows with their categories (`snapshot_delete`, `retention_prune`, `retention_gc`, `retention_remove`, `vm_delete`, `disk_delete`); the observed and verified rows come from listings and restore tests, which this pack does not produce.
2. **A reported success is not a loss;** it is a claim by the product. A failed deletion is not "nothing happened": a partial removal can leave a chain with a hole. Check the chain (`snapshots/chain-integrity`).
3. **A catalogue entry removed is not the bytes removed.** Many systems keep data until a later cleanup, or in a recycle or soft-deleted state. Ask what the product does for this version, and read the repository.
4. **Absence is bounded** (`evidence/coverage`): the source, the period, what the history keeps. Task history that rotates can lose the very request.
5. **Retention and expiry explain deletions only with the setting.** Match the removal's time and account to the policy; an off-schedule removal or a removal by an interactive account is a lead, not a finding.
6. **Name the claim that is safe.** "Deletion of X was requested by account A at T (record R); the product reported success; a listing at T2 no longer shows X; the repository was not listed" is a sentence the evidence can carry.

**Shows.** Which of the four states each object has evidence for. **Does not show.** Intent, the human, or that recovery is impossible: check surviving copies (`recovery/survivability`).
**Record.** Per object: each state, its source and locator, its time and clock, and what is unverified.
**Sensitive output.** Run `backup_audit_normalise` as a job with `secret_output: true`; cite an event's locator, not its message. An object or job name is shown only if plain, else `<withheld: N bytes, field F>`; hosts, actors, actions and messages have token-shaped runs, user-info and the value after `password=`-style names withheld; a short plain password passes unseen.
