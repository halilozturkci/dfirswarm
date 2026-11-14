---
id: backup/catalogues-and-retention
title: Catalogue, repository and retention
when: A backup system's catalogue, job records, repository or retention setting is evidence.
needs: []
card: backup_audit_normalise reads the Proxmox formats; another product only through a mapping you declare from its export, each event labelled declared. A missing time or action makes the answer partial. Result ok is the product's report, not a usable restore point. Does not show: that a restore works, that a deletion removed the bytes, or who the human was.
tools: [backup_audit_normalise]
requires_host: []
---

Use when you read what a backup system believes it holds, what its storage holds and what its settings say to keep. Not for the incident sequence (the ransomware pack's `encryptor/backup-infrastructure` and `encryptor/destroyed-backups`, if loaded).

1. **Keep three accounts apart.** The *catalogue* (the product's database of restore points and jobs) says what it believes exists; the *repository* holds the bytes; the *settings* (retention, schedules, immutability) say what should have been kept. Each can change separately.
2. **Say which products you can read.** `backup_audit_normalise` reads the Proxmox formats and presets (`backup/product-presets`) and any CSV, JSON Lines, JSON array or XML export through a mapping you declare. Another product has no reader: declare the mapping from its export's own header or schema. Never infer a vendor's layout from a sample or start the product against the evidence.
3. **Declare the mapping from the export, not from memory:** the fields for time, action, result, actor and object, how the time is written, and what each action means (`category_map`). Unmapped actions stay `other` with their raw name. A JSON Lines or XML field the records lack is counted in `declared_fields_absent` and a missing time or action, or a time that never parses, makes the answer `partial`; a CSV header without a declared column fails the file.
4. **Read the job record as a record.** Result `ok` shows the product reported success, not a usable restore point (`recovery/survivability`); a failure can be a storage, network or permission fault.
5. **Compare the accounts.** A point in the catalogue and not in the repository listing: bytes removed, never collected, or listed elsewhere. Bytes with no catalogue entry: the catalogue was lost, rebuilt or not collected. Do not decide from one side.
6. **Retention explains absence only when its setting and history are known.** A removal inside the window, or after a retention change, is not expiry: record the setting, when and by whom it changed, and whether the removal matches it.
7. **Immutability is a configuration plus a state.** Do not infer it from a label: record the mode, the objects' expiry, who could change it, and whether a listing shows them unexpired.

**Shows.** What the product recorded, as it recorded it. **Does not show.** That a restore works, that a deletion removed the bytes, or who the human was.
**Record.** Product and version as shown, export time, mapping, counts of events and unparsed lines, unmapped actions, and where the three accounts disagree.
**Sensitive output.** Run as a job with `secret_output: true`; cite the event's locator. Names show only if plain, else `<withheld N characters: reason>`; free text has secrets withheld; a short plain password passes.
