---
id: hypervisor/inventory
title: What VM configuration files and inventories list
when: VM configuration files, an inventory or a datastore listing name VMs, disks and snapshots.
needs: []
tools: [virtualization_inventory]
requires_host: []
---

Use when you hold configuration files or inventory exports and need the VMs, the disk files they name, their snapshots and datastores. Not for chain integrity (`snapshots/chain-integrity`) or for a product the tool does not list.

1. Give `virtualization_inventory` the whole directory. It reads VMware `.vmx`, `.vmsd` and `vmInventory.xml`, libvirt domain, snapshot and pool XML, and Proxmox VM configurations and `storage.cfg`. Hyper-V, VirtualBox and OVF files are listed as unsupported, not read: say so, and find another route (the Windows pack for Hyper-V host evidence).
2. **Read the counts first:** files in the set, parsed, unsupported, failed, and records per kind. A file that failed or was over a limit is a gap in the inventory, named in the answer.
3. **A listed VM is a configuration, not a running VM.** It does not show that the VM ran, exists now, or was not deleted; an inventory entry shows registration at the time the file was written. A configuration can be a copy.
4. **Check each disk reference.** `in_set: no` means the file was not among the files given. That is a bounded statement about the set; do not write "missing from the system". A hypervisor storage volume (an LVM or Ceph volume) is listed as not a file.
5. **Look at what the configuration says about protection.** A disk marked independent in a VMware configuration sits outside its snapshots, and a Proxmox disk with `backup=0` is left out of backup jobs, as the products' documentation describes; check the documentation for the version the image carries. These are candidates that a disk was never in a recovery point.
6. **Versions are strings.** Hardware version, machine type and similar fields are listed as written. Do not turn them into a product release without the vendor's documentation for it.
7. **Snapshots from configuration** carry the time only where the file states an epoch (Proxmox `snaptime`, libvirt `creationTime`). A VMware `.vmsd` keeps two raw fields that this tool does not decode; do not date a snapshot from them without a source that does.

**Shows.** What the files say was configured, with file and line or element. **Does not show.** That a VM, disk or snapshot exists, ran or was removed.
**Record.** Source ids, counts per kind, unsupported files, disks not in the set, credential-like keys (names, lines and sections, never values; a Proxmox snapshot or `special_sections` entry keeps its own copy of the settings).
**Sensitive output.** A console password, a cloud-init secret or a key may sit in a configuration: run it as a job with `secret_output: true`, report where the secret is and what it grants, and never use it.
