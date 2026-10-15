# Virtualization and Backup Forensics Pack

The control plane of virtualization and backup, read offline: what hypervisor
management records and VM configuration files say, whether a snapshot or disk
chain is whole, what a backup catalogue, job record and retention setting show,
and which recovery points survive. It reads exports and files; it never runs
hypervisor or backup software, reads no guest content and reaches no live system.

Depends on the Computer Forensics Base Pack. Guest artefacts belong to the
Windows, Linux and macOS packs, cloud snapshot APIs to the cloud pack, Hyper-V
event semantics to the Windows pack, Docker and containerd to the Linux pack, and
the order of a ransomware response to the ransomware pack. Disk-image extraction
and `qemu-img` and Dissect are the base pack's.

## What it carries

**Three skills,** one for each tool, as decision-rule leaves: `hypervisor/inventory`, `snapshots/chain-integrity`, `backup/catalogues-and-retention`. The router, the method leaves and the recovery skills follow in the next change.

**Three tools,** each with the standard library only and each saying what it did
not read:

- `virtualization_inventory` lists the VMs, disk files, snapshots and datastores
  that VMware `.vmx`, `.vmsd` and `vmInventory.xml`, libvirt domain, snapshot and
  pool XML, and Proxmox VM configurations and `storage.cfg` name, with the file
  and line or element of each statement. Hyper-V, VirtualBox and OVF files are
  recognised and listed as unsupported.
- `snapshot_chain_check` reads VMDK descriptors (text or embedded), VHD, VHDX and
  QCOW2 headers and the `.vmx`/`.vmsd` names, and reports each disk, parent edge,
  extent and chain with its identity check, plus markers (an unclean close, a
  leftover delta, a lock artefact) as candidates. `qemu-img` runs only when asked.
- `backup_audit_normalise` turns the Proxmox VE and Proxmox Backup Server task
  index (both UPID layouts) and Proxmox VE task logs, or an export of any product
  read through a mapping the caller declares, into canonical events. Any other product is `unsupported`
  until fixtures for it exist.

## What a tool shows of a name

Evidence names are attacker-controlled text, so the three tools judge every string
by the field it fills. A VM, host, datastore, snapshot or key name, a path or file
name, an identifier of a known kind (GUID, VMFS volume id, `naa.`/`t10.`/`wwn-`
device id, VMware uuid, MAC, CID) and a simple value (a version, an enum word, a
time) is shown only when it fits a plain grammar for its kind; anything else is
`<withheld: N bytes, field F>`, and the original goes to a 0600 file only with
`write_text` in a job. Free text (a description, an annotation, an audit action or
actor, a message) has token-shaped runs, user-info and the value after a name that
says it is a secret withheld, and a second check, written apart from the first
two, reads the serialised answer back. This is a heuristic, not a guarantee: a
short password used as a name is not recognised, so the skills say to run the tools
as jobs with `secret_output: true`.

## Two things the skills keep repeating

**A record is not the state.** A request to delete, a job that reports success, a
catalogue entry that is gone and a repository whose bytes are gone are four
different facts. The skills keep them apart and say which evidence shows each.

**Never run the product.** Powering on, importing, consolidating, committing or
restoring from an evidence VM or backup can rewrite the very chain being
examined, and a credential in a configuration is an indicator, not a login.

## Not covered

Products with no reader here are `unsupported` until anonymised exports exist:
Veeam, Commvault, Rubrik, Cohesity, Acronis, NetBackup, vCenter's database and
events, Hyper-V's binary configuration, Nutanix, oVirt and XenServer. A declared
mapping can read a CSV, JSON Lines or XML export of any of them, and says it is
declared.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/virtualization-backup-forensics
    scripts/swarm.sh start --pack computer-forensics-base,virtualization-backup-forensics ...
