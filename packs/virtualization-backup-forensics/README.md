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

**Twelve skills**, a router, a method leaf and ten decision-rule leaves:
`router/start`, `evidence/boundaries`, `control-plane/chronology`,
`hypervisor/activity`, `hypervisor/inventory`, `snapshots/chain-integrity`,
`snapshots/markers`, `snapshots/header-markers`, `backup/catalogues-and-retention`,
`backup/deletion-vs-loss`, `backup/product-presets`, `recovery/survivability`.

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
  index (both UPID layouts), Proxmox VE task logs, Proxmox Backup Server task log
  files, configuration files and data blobs (not decrypted, not inflated), the
  Proxmox Backup client's JSON snapshot listing (a preset), or an export of any
  product read through a mapping the caller declares (CSV, JSON Lines, a JSON
  array or XML), into canonical events. The Proxmox Backup readers are built from
  the product's documentation and source and the Proxmox VE ones from synthetic
  fixtures; none is validated against a real export, and every answer says so
  (`provenance`). Any other product is `unsupported` until a reader for it exists.

**One goal template**: `what-recovery-survives.md`.

## What a tool shows of a name

Evidence names are attacker-controlled text, so the three tools judge every string
by the field it fills, with the one boundary text that the Windows and macOS tools
carry too (the same text in all 16 carriers, held equal by a repo-wide test). A VM,
datastore, snapshot or key name, a path or file name, an identifier of a known kind
(GUID, VMFS volume id, `naa.`/`t10.`/`wwn-` device id, VMware uuid, MAC, CID) and a
simple value (a version, an enum word, a time) is shown only when it fits a plain
grammar for its kind; anything else is `<withheld N characters: reason>`, and the
original goes to a 0600 file (`<tool>-values.jsonl`, next to the tool's text file)
only with `write_text` in a job run as secret output. Free text (a description, an
annotation, an audit action or actor, a message) has token-shaped runs, user-info and
the value after a name that says it is a secret withheld, and a second check, written
apart from the first two, reads the serialised answer back; a string it replaces
makes the answer partial. This is a heuristic, not a guarantee: a short password used
alone as a name is not recognised, nor, after a secret's name, a value of 6
characters or fewer or one built like words, nor a name the grammar of a plain name
refuses (a machine name with several one-letter pieces, such as `ProxyK8sMgmtNode10`,
is withheld although it is no secret, and so is, in about one path in eight, the part of a path that holds a
Windows default name such as `WIN-0N02YXG158X`), so the skills say to run the tools as jobs with
`secret_output: true`.

## Two things the skills keep repeating

**A record is not the state.** A request to delete, a job that reports success, a
catalogue entry that is gone and a repository whose bytes are gone are four
different facts. The skills keep them apart and say which evidence shows each.

**Never run the product.** Powering on, importing, consolidating, committing or
restoring from an evidence VM or backup can rewrite the very chain being
examined, and a credential in a configuration is an indicator, not a login.

## Not covered

Products with no reader or preset here are `unsupported` until anonymised exports exist:
Veeam, Commvault, Rubrik, Cohesity, Acronis, NetBackup, vCenter's database and
events, Hyper-V's binary configuration, Nutanix, oVirt and XenServer. A declared
mapping can read a CSV, JSON Lines, JSON array or XML export of any of them, and
says it is declared.

## A program that leaves a process behind

With `qemu_img`, `snapshot_chain_check` reports what `qemu-img info` printed on a pipe. The pipe of a `qemu-img` that has ended is read for at most one more second and 1 MiB and then let go (what still holds it is ended first), so a
process it left running does not hold the call, and a `qemu-img` that exited is not reported as timed out. A process the shared process block had to end makes the answer
`partial` (a line in `partial_reasons`); a host that cannot adopt orphans (not Linux, or the kernel refuses `PR_SET_CHILD_SUBREAPER`) does not, and `program_group.unproven` says
it. A call that ran `qemu-img` carries `program_group` (`subreaper`, `left_behind`, `unproven`, `notes`). The other tools of the pack start no program.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/virtualization-backup-forensics
    scripts/swarm.sh start --pack computer-forensics-base,virtualization-backup-forensics ...
