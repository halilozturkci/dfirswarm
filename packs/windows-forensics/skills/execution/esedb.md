---
id: execution/esedb
title: ESE databases
when: Export tables from SRUDB.dat and others.
needs: []
tools: [esedb_query]
requires_host: [esedbexport]
---

Use when you read an ESE database through `esedb_query`. Not for what the tables mean: open `execution/srum` only if the database is SRUDB.dat, `browser/webcache` only if it is a WebCache.

- **What it does.** It runs `esedbexport` and returns TABLES as text: with no `table` it lists them, with one it returns the rows, each numbered `_row` by its line in the exported file. It decodes nothing, joins nothing, resolves no container and reads no ESE log, so a database in a dirty state may lack its newest rows.
- **Read the accounting first:** `status` (`complete`, `partial`, `failed`; `interrupted` is a stop by signal and no result), `exporter_exit_status`, `timed_out`, `exporter_version`, `db_sha256`. The export is made once per database into `esedb-export/<first 16 hex of db_sha256>/` (`export_dir`, the tables); the exporter's whole output is in `stdout_file` and `stderr_file` beside it, not in `export_dir`. A complete export is reused (`export_reused`) only if this version wrote it, its exit status was 0 and every listed table file is on disk at its recorded size; otherwise it is exported again. Cite the export by its manifest, not by a count you remember.
- **Partial.** A non-zero exit or `export_timeout_seconds` leaves a partial export: its tables are listed only as `tables_in_partial_export`, and a table missing or short there is not absent from the database.
- A table name matching more than one export file is refused with the candidates; name one. A repeated column name is numbered. The table is read as plain tab-separated text. Rows shown inline are bounded (256 KiB; a cell over 4,096 characters is shown cut, `_cells_shortened`); `all_results` holds every row as the boundary shows it (the whole table is in `export_dir`).
- **Sensitive output.** The export directory holds every table whole (mode 0700, files 0600; `export_dir_sensitive`) and is a sensitive output of the job: run `esedb_query` as a job with `secret_output: true` and cite by file and table. Rows withhold, with a marker that holds only the length, the cells of columns named for a password, secret, token, encryption, credential, card, IBAN or SSN, and the credential attributes of an Active Directory datatable (`columns_withheld`), and URL secrets by parameter name and user-info shape (`url_secrets_withheld`; a secret in a URL path, a title or free text is not covered; `write_url_secrets` writes them in full to a 0600 file, in a job only). Table, column and cell text is also judged by shape (`boundary`; a plain password or a UUID-shaped key is printed); binary cells exported as hex are decoded and judged by their printable text, and hex with no text in it is printed. Withheld table names are listed in an order that changes each run. `write_values` (secret job only) writes the withheld originals.

Shows: the tables the exporter produced, accounted. Does not show: what a table or column means, that an export is the whole database, or what a partial export lacks. Record: `db_sha256`, the export manifest, `status`, table, `_row`.
