---
id: security/tcc
title: TCC privacy permission records
when: An answer depends on which application was allowed or refused camera, disk, accessibility or other privacy access.
needs: []
card: macos_tcc reads one TCC.db per call and never merges the system and user stores; cite the columns the file has. auth_value 0 to 3 is decoded in auth_value_meaning; any other number stays raw and makes the answer partial. last_modified_utc is when the row was last written, not the grant time. managed means policy_id is set. A partial read goes on with after_rowid. Does not show: use of the permission, who approved it, or a store not acquired.
tools: [macos_tcc]
requires_host: []
---

Use when a question asks what privacy permission an application held or was refused. Not for login and background items (`persistence/login-items-quieter`) or for whether an application used a permission.

**Stores.** The system database (`/Library/Application Support/com.apple.TCC/TCC.db`) and each user's (`~/Library/Application Support/com.apple.TCC/TCC.db`) are separate records. Take a `TCC.db` with its `-wal`, `-shm` and `-journal` as one set and call `macos_tcc` once per file; it reads a private copy with the log applied and never merges the system and user stores. Inventory every user's before saying a permission was absent.

**Schema first.** Columns differ by build. The tool reads the file's own table definition and the `admin` version row, and shows every column raw under `columns` (`access_columns` lists them). Cite the columns the file has, not the ones you expect.

**Reading a row.** Only these are decoded, with the raw number beside: `auth_value` 0, 1, 2, 3 as denied, unknown, allowed, limited (`auth_value_meaning`) and `client_type` 0 or 1 as bundle identifier or absolute path. Any other number, and `auth_reason`, stay raw: report "other" with the number. A value outside 0 to 3 is listed under `problems` and the answer is `partial`. `managed` is true when `policy_id` is set, a configuration-profile or MDM policy and not a user's choice; it is null when the schema has no `policy_id`. The code-signing requirement is shown by length only.

**Time.** `last_modified_utc` is when the row was last written: a grant, a revoke, a reset or a system update each move it. It is not the time of a grant; `last_reminder_utc` is when the user was reminded. A grant time needs other evidence (the unified log, `logs/unified`, if retained).

**Authorization is not access.** An allowed row shows what the store held at acquisition. It does not show that the application used the permission, that a person approved it, or when. A missing row is not a refusal and not proof of no grant: a reset removes rows, and a store not acquired is not read.

Shows: a stored decision per service and client, whether it is managed, and the row's last write. Does not show: use of the permission, who approved it, the grant time, or a store that was not acquired.
Record: which database (system or whose), the schema columns and `admin` version, `rowid`, service, client, `client_type`, `auth_value` raw, `managed`, `last_modified_utc` with its raw number, `problems`.
Sensitive output: services, clients and paths pass the shared boundary by shape, so a token-shaped client is withheld and another secret shape is printed. The tool has no values mode. Cite the `rowid`.
