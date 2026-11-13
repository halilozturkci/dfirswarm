---
id: data/sqlite-secrets
title: Secret tables without the values
when: A table holds cookies, logins, tokens or keys.
needs: []
tools: [sqlite_query]
requires_host: []
---

Use only if `data/sqlite` sends you here: a table of cookies, logins, tokens, keys or private messages. Not for ordinary application data (`data/sqlite`).

**Allowed: in a job, the values to a file.** The one way to read such a table (a browser's `Login Data`, `Cookies`, `key4.db` too): a job with `secret_output: true`, `table` (and `columns`, or `rowid_from` and `rowid_to` for a part) and `write_values: true`; refused outside a job or without secret output.

    job_run(tool: "sqlite_query", secret_output: true, args: {"db_path": "<snapshot or database>", "table": "logins", "write_values": true})

**Not allowed:** `sql` over the values, anywhere (a `WHERE` or `LIKE` on one confirms a guess). A browser's stored passwords stay encrypted there.

The values go only to `sqlite-query-values.jsonl` under `{OUT}` (mode 0600, a line per cell, then an end line: without it the file was cut short). The answer has each cell as `type:length`, per-column counts and the first rows; `locators_file` has every row. One file per job, made once the table is found: a wrong name leaves nothing; export again in a new one. Hand a value on only through the channel the operator named.

**What locates a row** (`table_kind`; `n_ranks`: the columns `n` follows). Ordinary table: `rowid`, SQLite's row key, no column's value unless the application set it; a range selects by it. A sole primary key column declared `INTEGER`: that column is the rowid, so the rowid is a value: never printed, a range refused (`rowid_is_a_value`), rows located by their position `n`, which ranks the key's values. WITHOUT ROWID: `n` in primary key order, which ranks those values too. `shadowed` (columns named rowid, oid and _rowid_): `n`. Virtual: `n`, in the module's order, or `virtual_table_unsupported`.

**Lengths.** An integer's length is its decimal digits (a PIN stored as an integer has lost its leading zeros). A real's is not (`1e+20` is `real:5`). `cells_not_exported` lists a cell over the length limit (`value_too_large`) or one SQLite cannot compute (`unreadable`); the rest is exported; a row with no readable cell stops it (`row_unreadable`). Which cells are `unreadable` follows from the values: it says something of them. `values_file_error` (a full disk; `ok` false): `values_file_holds` says what it holds.

**Fallback, outside a job or without the mode.** `limit` is 1 or more, so the inline page always carries at least one row of values: on such a table select only locators (`rowid`, `length(col)`, `typeof(col)`) `FROM t NOT INDEXED ORDER BY rowid`, never the column itself (an index on it would rank them). WITHOUT ROWID: `ORDER BY` the key, which ranks it. Where a column is the `INTEGER PRIMARY KEY`, `rowid` is its value: leave it out.

**Record.** Table, the locator (`rowid`, or `n` where `locator` is `n`), column, type and length of each cell cited, and the values file's name; never the value, a fragment of it, or the `sha256` and base64 of a short BLOB.

**Does not show.** A type and a length show a cell is filled and how big, not what it holds, whether it is valid or current, or what it opens. Run time follows values over 1 MiB.

**Sensitive output.** The values file is a sealed secret output.
