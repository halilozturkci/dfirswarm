---
id: hypervisor/activity
title: What to ask of hypervisor management records
when: A VM was powered off, deleted, unregistered, snapshotted, reconfigured or its datastore changed.
needs: []
card: A task record from backup_audit_normalise shows an operation ran under an account, not the person. A gap in one plane's records is not a gap in the event. A VM in a record and in no virtualization_inventory listing is a question, not a finding. Does not show: the person, intent, or that the operation completed.
tools: [backup_audit_normalise, virtualization_inventory]
requires_host: []
mentions: [evtx_query]
---

Use when the question is what was done to a VM, a snapshot or a datastore through the management plane. Not for the incident sequence of a ransomware case (that pack's `encryptor/backup-infrastructure`, if loaded) or for what ran inside the guest.

1. **Ask five things of every record:** which operation, on which object, under which account or token, from which source address or session, and the outcome, each with the record's own time. A task record shows an operation ran under that account, not the person.
2. **List the planes that could have recorded it.** The management server's tasks and events; the host's own, shell and authentication logs; the hypervisor's local API log. An operation made on a host through its shell or API may be absent from the management server's records, and one made through the server recorded at both ends: check what each export keeps. A gap in one is not a gap in the event.
3. **Where the platform is Proxmox,** `backup_audit_normalise` reads the Proxmox task and log formats (`backup/product-presets`). Any other product's export needs a declared mapping (`format: declared_csv`, `declared_jsonl` or `declared_xml`), and every such event is labelled declared. Log names and locations differ by product and version: list the bundle before assuming one is missing.
4. **Operations worth separating:** snapshot create, remove and revert; VM delete or unregister (a record removed from inventory leaves its files); disk file delete; power off or reset; reconfiguration (a disk changed to one that snapshots or backups skip); datastore or repository removal; console or shell enablement; a new account's access. Each is a lead.
5. **Check the inventory against the records.** `virtualization_inventory` lists what the configuration files say existed; a VM in a record and in no inventory, or the reverse, is a question about collection or deletion, not yet a finding.
6. **A bounded negative:** "no snapshot-removal task in source A, from T1 to T2, by worker type X" and nothing wider. Retention and rotation of the task history decide whether an operation would still be there.
7. For Hyper-V, the host's event channels are Windows evidence (the Windows pack's `evtx_query`, when loaded).

**Shows.** An operation, object, account and time as the system recorded them. **Does not show.** The person, intent, or that the operation completed as the VM's files now stand.
**Record.** Source, record locator, operation, object, account, address, outcome, clock, and the planes you did not have.
**Sensitive output.** Run the tools as jobs with `secret_output: true`; cite the locator, not the text. Names show only if plain, else `<withheld N characters: reason>`; free text has secrets withheld; a short plain password passes unseen.
