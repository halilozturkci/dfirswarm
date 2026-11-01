---
id: platforms/esxi-hypervisors
title: ESXi hosts, management plane and datastores
when: An ESXi host, its management server, guests or datastores were encrypted or altered.
needs: []
tools: []
requires_host: []
mentions: [virtualization_inventory, snapshot_chain_check, backup_audit_normalise]
---

Use when an ESXi host, its management server, its virtual machines or its datastores were encrypted, powered off or altered. Not for the backup server or the recovery inventory (`encryptor/backup-infrastructure`, `encryptor/destroyed-backups`).

**Four layers, kept apart.** The host (its shell, services and local accounts), the
management plane (the management server, its roles and its audit), the guest (its
operating system and disks) and the datastore (the volumes and files under the
machines). A finding at one layer does not carry to another: encrypted disk files on
a datastore do not show that a guest ran the encryptor, and a compromised management
account does not show that the host's shell was used. Say which layer each record
belongs to before it enters the timeline.

**Preserve before you touch.** Take the host's support bundle (its content differs by
version: record the version and build), the management plane's task and event
records, the authentication and shell activity (logins, remote-access and
shell-history records), each machine's configuration file, its virtual-disk
descriptors, the backing extents and the snapshot chains. Do not consolidate or
delete a snapshot, power on, register or migrate a machine, or reboot the host
before the chain metadata is preserved: consolidation rewrites it, and a reboot
loses what the host kept in memory.

**Tools.** If the virtualization-backup-forensics pack is loaded (check the run's
tool inventory), `virtualization_inventory` lists the machines, disk files and
snapshots that configuration files name, `snapshot_chain_check` tests whether a disk
or snapshot chain is whole, and `backup_audit_normalise` reads Proxmox task logs and
exports whose fields the caller maps, and no other product's records. Check that each answer says what it did not read, and say so where it
does not. Where the pack is not loaded, say that no tool read this evidence.

**Shows.** Which layer a record belongs to; which machines, disks and snapshots the
configuration names; whether a named chain is whole on the copy examined.

**Does not show.** A virtual-machine snapshot is not an independent backup, and the
loss of a base or dependent disk can invalidate a chain. A powered-off machine does
not show encryption; a missing
snapshot does not show who deleted it or when; a management-plane login does not show
what was done with it; a datastore listing taken after the incident does not show
the state before it.

Record: the host version and build, each source and the layer it came from, the
chain metadata as preserved (with its hash), and every action taken on the
environment, with who authorised it.
Sensitive output: support bundles and configuration files can hold credentials,
keys and tokens; cite the file and the field, never the value.
