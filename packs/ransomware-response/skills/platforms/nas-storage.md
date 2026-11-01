---
id: platforms/nas-storage
title: Network storage, shares and replication
when: A NAS appliance, its shares, snapshots or replication were encrypted or altered.
needs: []
tools: []
requires_host: []
mentions: [virtualization_inventory, snapshot_chain_check, backup_audit_normalise]
---

Use when a network-attached storage appliance, its shares, its snapshots or its replication partners were encrypted or altered. Not for the backup server or the hypervisor (`encryptor/backup-infrastructure`, `platforms/esxi-hypervisors`).

**Three routes, kept apart.** Encrypted files on a share may have been written from
a client that held the share open, or by someone with the appliance's management
plane, or they may be damaged data that replication copied from another system.
Each route leaves different records and has a different containment. A client that
wrote through a share is the client's evidence; a compromised management plane puts
the appliance's own snapshots and retention in question; replication carries damage
to a partner and may expire the good versions there.

**Preserve before you restore.** Take the appliance's support bundle (record the
product, version and build), the administrative audit, the share access logs,
the snapshot inventory with each snapshot's creation time and retention, the
replication inventory and its job history, and the retention and lock settings. Do
not delete, roll back or expire a snapshot, or end a replication relationship,
before those are preserved. Hold the replication partner's records too.

**Imaging.** One member of a RAID set, imaged alone, is not a logical acquisition of
the volume: say what was acquired (a member, the volume, a share, a snapshot) and
what the result cannot reach.

**Tools.** If the virtualization-backup-forensics pack is loaded (check the run's
tool inventory), its tools may read machine files kept on the storage:
`virtualization_inventory`, `snapshot_chain_check` and `backup_audit_normalise`.
Where it is not loaded, say that no tool read this evidence.

**Shows.** Which route the records support; which snapshots existed and until when;
which partner received what.

**Does not show.** A share that became unavailable does not show that its data or
snapshots were destroyed; an intact snapshot does not show that the live data is intact; a replication job marked
successful does not show that the copy is usable.

Record: the appliance version, each source, the audit window, the snapshot and
replication inventories as found, and each action taken, with who authorised it.
Sensitive output: appliance bundles and audits can hold credentials, keys and share
secrets; cite the record, never the value.
