---
id: encryptor/destroyed-backups
title: Recovery impairment and surviving recovery paths
when: Backups, snapshots, catalogues or recovery services may have been altered.
needs: []
tools: [backup_destruction_correlate]
requires_host: []
mentions: [vss_stores]
---

Use when backups, snapshots, catalogues or recovery services may have been altered. Not for the backup server or hypervisor detail.

Treat recovery impairment as its own sequence. Do not assume it came just before
the encryption, or that every destructive-looking action succeeded.

**Build a recovery inventory.** For each production dataset list the local
snapshots, backup repositories, replicas, offline copies, immutable copies, cloud
versions and the encryption keys they need. Record ownership, administrative
boundaries, retention, the last successful job and the last verified restore. A
job marked successful is not a demonstrated usable restore.

**Windows shadow copies.** Look for process and audit evidence of snapshot
deletion, shadow-storage changes, backup administration and recovery-setting
changes: the shadow-copy utilities' delete verbs, their WMI and PowerShell
equivalents, a storage resize. These are commands to recognise in a log or a
history, not to run on the examination host. Command-line and script logging may
not have been on, and an unattended run need not appear in an interactive history.
If the windows-forensics pack is loaded (check the run's tool inventory), its
`filesystem/shadowcopies` skill and `vss_stores` read the stores; check that the
tool's answer separates a store that is absent from one it could not read, and say
so where it does not.

Separate an attempted deletion, a reported success and an independently verified
loss. Finding no stores can also mean protection was disabled, retention or storage
pressure removed them, the acquisition did not include them, the parser failed or
the wrong volume was searched. State the volumes and snapshots covered, and check
for surviving copies, before concluding that a path was lost.

`backup_destruction_correlate` keeps five observations apart per host and object, from
answers given by reference: command seen, action attempted, reported outcome, inventory
change and verified loss. It reports a command with no inventory change, and a change
with no command, as such. A command that ran is not a copy that is gone; only a
verification made apart from the logs says a path was lost.

Only if a backup server, an immutable store, a hypervisor, network storage or a boot-recovery setting was affected: `encryptor/backup-infrastructure`.

**Preserve before repair.** Record the state before any catalogue rebuild,
snapshot consolidation, repository repair or retention change. Where urgent
restoration has to go first, record who authorised it, which sources it touched and
the evidence it cost.

**Does not show.** Missing stores do not show deletion; a recovery-setting change is not a signature.

**Deliver** one row per recovery object or chain: the expected state, the observed
action, the account where supported, time and clock, outcome, surviving copies,
restore-test status, evidence and confidence. Call an impairment deliberate only
where the evidence supports both the act and that inference.
