---
id: backup/catalogues-and-retention
title: Catalogue, repository and retention
when: A backup system's catalogue, job records, repository or retention setting is evidence.
needs: []
tools: [backup_audit_normalise]
requires_host: []
---

Use when you read what a backup system believes it holds, what its storage holds, and what its settings say should be kept. Not for the incident sequence (the ransomware pack, if loaded) or for a product the tool does not list.

1. **Keep three accounts apart.** The *catalogue* (the product's database of restore points and jobs) says what the product believes exists. The *repository* (files or objects on storage) holds what bytes exist. The *settings* (retention, schedules, repository and immutability configuration) say what should have been kept and removed. Each can be changed, lost or collected separately.
2. **Say which products you can read.** `backup_audit_normalise` reads Proxmox VE and Proxmox Backup Server task indexes (both UPID layouts) and Proxmox VE task logs, and any CSV, JSON Lines or XML export through a mapping you declare. For another product there is no reader here: ask for an export, declare the mapping from the export's own header or schema, and label every event as declared. Do not infer a vendor's layout from a sample, and never start the product against the evidence.
3. **Declare the mapping from the export, not from memory:** which field is the time, the action, the result, the actor and the object, how the time is written, and what each action means (`category_map`). Unmapped actions stay `other` with their raw name; list them and ask the owner what they mean. A JSON Lines or XML field the records lack is counted in `declared_fields_absent`, and a missing time or action makes the answer `partial`; a CSV header without a declared column fails that file, nothing read. Fix the mapping, do not read on.
4. **Read the job record as a record.** A job with result `ok` shows the product reported success. It does not show a usable restore point. A failure can be a storage, network or permission fault.
5. **Compare the accounts.** A restore point in the catalogue and absent in the repository listing: bytes removed, never collected, or listed under another path. Bytes in the repository with no catalogue entry: the catalogue was lost, rebuilt or not collected. Do not decide which from one side.
6. **Retention explains absence only when its setting and history are known.** A removal inside the retention window, or a retention change before the removal, is a separate question from expiry: record the setting, when it changed, by which account, and whether the removal matches it.
7. **Immutability is a configuration plus a state.** Do not infer protection from a label. Record the mode, the expiry of the objects, who could change it, and whether a listing shows the objects unexpired.

**Shows.** What the product recorded, as it recorded it. **Does not show.** That a restore works, that a deletion removed the bytes, or who the human was.
**Record.** Product and version as shown, export time, mapping declared, counts of events and unparsed lines, unmapped actions, the three accounts and where they disagree.
**Sensitive output.** Messages and object paths can carry names and tokens: run as a job with `secret_output: true`; cite the event's locator.
