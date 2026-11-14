---
id: backup/product-presets
title: Backup formats and presets the tool reads
when: Say which backup export backup_audit_normalise can read, and how far to trust it.
needs: [backup/catalogues-and-retention]
card: backup_audit_normalise: format auto does not find a Backup Server task log; name it ({"format": "pbs_task_log"}). No reader is validated against a real export: read provenance and preset. An unparsed line, a log with no closing TASK line, a compressed or encrypted blob or a CRC mismatch makes the answer partial. A preset and a mapping are not mixed. Does not show: that the reader matches a real product's file, or that a listed point restores.
tools: [backup_audit_normalise]
requires_host: []
---

Use when you choose a format or preset for a `backup_audit_normalise` run. Not for what the events mean (`backup/catalogues-and-retention`) or for a product this list does not name.

Each reader below is built from documentation or from synthetic fixtures; none is validated against a real export. The answer says so (`provenance`, and `preset` where one was used). A line or record off the documented shape is counted `unparsed` and located, never guessed, and the answer is `partial`.

1. **Proxmox task index and vzdump log** (`pve_task_index`, `pve_vzdump_log`): found by `auto`; built from synthetic fixtures only.
2. **Backup Server task log** (`pbs_task_log`): name it, `auto` does not find it. Lines are `<RFC 3339 time>: <message>`, ending in a `TASK OK`, `TASK WARNINGS`, `TASK ERROR` or `TASK unknown` line; no closing line is `partial`. A message's category is the tool's keyword table; its text is not printed. A time with no zone stays raw.
3. **Backup Server configuration** (`pbs_config`): `datastore.cfg`, `prune.cfg`, `sync.cfg`, `verification.cfg`, `remote.cfg`, found by `auto` from the file name and first section. Settings are records; the retention ones (`keep-*`, `gc-schedule`, `prune-schedule`, `schedule`, `notify`) are marked `retention_setting`. A comment, a password or a key is never printed.
4. **Backup Server data blob** (`pbs_blob`): found by `auto` from its magic. An uncompressed `index.json.blob` gives the snapshot and its files, sizes and checksums; `client.log.blob` gives lines. A compressed blob is counted and not inflated; an encrypted one is identified and never decrypted; both are `partial`. A CRC mismatch is `partial`.
5. **Preset** `proxmox_backup_client_snapshot_list` (`product: proxmox_backup_client`): a JSON array from `snapshot list --output-format json`. A vm, ct or host snapshot is labelled `backup_end` (the datastore holds it, not that it restores), any other type `other`; the result is `unknown`.
6. **Your own mapping** (`declared_csv`, `declared_jsonl`, `declared_json`, `declared_xml`): the labels are yours, and every event says declared. A preset and a mapping are not mixed; a changed preset file is refused by name.

No other product has a reader: ask for an export and declare its mapping. Run the tool as a job with `secret_output: true`; cite an event's locator, not its message.

**Shows.** What a file or listing says, and which reader and source it came through. **Does not show.** That the reader matches a real product's file, or that a listed point restores.
**Record.** Format or preset with its revision, the provenance, and the counts of unparsed lines.
