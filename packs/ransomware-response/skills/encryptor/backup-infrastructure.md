---
id: encryptor/backup-infrastructure
title: Backup servers, immutable storage and hypervisors
when: A backup server, immutable store, hypervisor or recovery setting was affected.
needs: []
tools: []
requires_host: []
---

Use only if a backup server, an immutable or versioned store, a hypervisor, network storage or a boot-recovery setting was affected. Not for the recovery inventory (`encryptor/destroyed-backups`).

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

**Hypervisors and network storage.** For a hypervisor read `platforms/esxi-hypervisors`;
for network storage read `platforms/nas-storage`. They hold what to preserve, how
to separate a guest's compromise from the host's or the storage's, and which tools
of the virtualization pack read the evidence, if it is loaded.

**Boot recovery and stopped services.** Record changes to the recovery
configuration (the boot manager's recovery and boot-status settings, the recovery
environment) and what each did. They neither show that backups were destroyed nor
identify a family. A database or virtual-machine service stop may have made files
available to encrypt, but its time does not mark the encryption to the second:
correlate it with later file and application evidence, and consider routine
maintenance and response actions.

**Does not show.** A backup server's compromise does not show that every copy is lost; a stopped service does not show intent or timing of the encryption; an unavailable share does not show its data was destroyed.

Record: the backup server's audit and job records, retention mode and expiry of immutable objects, the management-plane audit, what each recovery-setting change did.
Sensitive output: backup repositories and configurations can hold credentials and keys; cite the records, never the values.
