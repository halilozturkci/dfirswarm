---
id: backup/catalogues-and-retention
title: Catalogue, repository and retention
when: A backup system's catalogue, job records, repository or retention setting is evidence.
needs: []
tools: [backup_audit_normalise]
requires_host: []
---

Use when you read what a backup system believes it holds, what its storage holds, and what its settings say should be kept. Not for the incident sequence (the ransomware pack's `encryptor/backup-infrastructure` and `encryptor/destroyed-backups`, if loaded) or for a product the tool does not list.

1. **Keep three accounts apart.** The *catalogue* (the product's database of restore points and jobs) says what it believes exists; the *repository* (files or objects on storage) holds what bytes exist; the *settings* (retention, schedules, repository and immutability configuration) say what should have been kept. Each can change separately.
2. **Say which products you can read.** `backup_audit_normalise` reads Proxmox VE and Proxmox Backup Server task indexes (both UPID layouts) and Proxmox VE task logs, and any CSV, JSON Lines or XML export through a mapping you declare. Another product has no reader here: ask for an export and declare the mapping from its own header or schema, labelling every event declared. Never infer a vendor's layout from a sample or start the product against the evidence.
3. **Declare the mapping from the export, not from memory:** which field is the time, the action, the result, the actor, the object, how the time is written, and what each action means (`category_map`). Unmapped actions stay `other` with their raw name. A JSON Lines or XML field the records lack is counted in `declared_fields_absent` and a missing time or action, or a time that never parses, makes the answer `partial`; a CSV header without a declared column fails the file.
4. **Read the job record as a record.** A job with result `ok` shows the product reported success. It does not show a usable restore point (`recovery/survivability`). A failure can be a storage, network or permission fault.
5. **Compare the accounts.** A restore point in the catalogue and absent in the repository listing: bytes removed, never collected, or listed elsewhere. Bytes in the repository with no catalogue entry: the catalogue was lost, rebuilt or not collected. Do not decide from one side.
6. **Retention explains absence only when its setting and history are known.** A removal inside the retention window, or a retention change before the removal, is not expiry: record the setting, when it changed, by which account, and whether the removal matches it.
7. **Immutability is a configuration plus a state.** Do not infer protection from a label. Record the mode, the objects' expiry, who could change it, and whether a listing shows them unexpired.

**Shows.** What the product recorded, as it recorded it. **Does not show.** That a restore works, that a deletion removed the bytes, or who the human was.
**Record.** Product and version as shown, export time, mapping declared, counts of events and unparsed lines, unmapped actions, the three accounts and where they disagree.
**Sensitive output.** Run as a job with `secret_output: true`; cite the event's locator. Plain object and job names are shown, else `<withheld: N bytes, field F>`; hosts and free text have tokens, user-info and `password=` values withheld; a short plain password passes.
