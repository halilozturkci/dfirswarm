---
id: encryptor/destroyed-backups
title: Establishing recovery impairment and surviving recovery paths
when: Backups, snapshots, catalogues or recovery services may have been altered.
needs: [encryptor/traces]
tools: []
requires_host: []
mentions: [vss_stores]
---

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

**Backup infrastructure.** Preserve the backup server's audit and job records, the
repository metadata, catalogue and configuration, identity events, deletion
requests and their outcomes, and any logs kept elsewhere. A stopped agent, a
deleted catalogue or a compromised administrator account does not show that all
backup data was destroyed. Check whether the catalogue can be rebuilt and whether
an offline, separate-account or immutable copy survives.

For immutable or versioned storage check the objects themselves: retention mode,
expiry, legal holds, lifecycle changes and the administrative rights that can
bypass them. Do not infer protection from a product label. Establish that the
keys and the whole backup chain are still available.

**Hypervisors and network storage.** Preserve the management-plane audit records,
the storage and snapshot inventories, the replication history and task outcomes.
Separate a guest's compromise from the host's or the storage's. A virtual-machine
snapshot is not an independent backup, and the loss of a base or dependent disk can
invalidate a chain. A share that became unavailable does not show that its data or
snapshots were destroyed.

**Boot recovery and stopped services.** Record changes to the recovery
configuration (the boot manager's recovery and boot-status settings, the recovery
environment) and what each did. They neither show that backups were destroyed nor
identify a family. A database or virtual-machine service stop may have made files
available to encrypt, but its time does not mark the encryption to the second:
correlate it with later file and application evidence, and consider routine
maintenance and response actions.

**Preserve before repair.** Record the state before any catalogue rebuild,
snapshot consolidation, repository repair or retention change. Where urgent
restoration has to go first, record who authorised it, which sources it touched and
the evidence it cost.

**Does not show.** Missing stores do not show deletion; a backup server's
compromise does not show that every copy is lost; a stopped service does not show
intent or timing of the encryption; a recovery-setting change is not a signature.

**Deliver** one row per recovery object or chain: the expected state, the observed
action, the account where supported, time and clock, outcome, surviving copies,
restore-test status, evidence and confidence. Call an impairment deliberate only
where the evidence supports both the act and that inference.
