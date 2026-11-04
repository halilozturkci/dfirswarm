---
id: execution/srum
title: SRUM
when: Application byte counts, CPU, network; limits.
needs: [execution/esedb]
tools: [srum_reader, esedb_query]
requires_host: [SrumECmd, dotnet]
---

Use when you interpret rows of the System Resource Usage Monitor database. Not for exporting raw tables (`execution/esedb`, read it before you cite a row) or for deciding that data left (`execution/overview`).

- **Source.** `C:\Windows\System32\sru\SRUDB.dat` is an ESE database with several accounting tables of different schemas and interval semantics. Collect it with the ESE log and checkpoint files beside it and the `SOFTWARE` hive, keep the originals untouched, and do any recovery on a derivative you record.
- **Reading it.** `srum_reader` runs SrumECmd (through dotnet) and dissect.target where installed and keeps every row in a file, with the `backend` that produced it. Read `backends` first: SrumECmd refuses to run off Windows (`unsupported_platform`) and dissect needs a collection directory, so a Linux image may give no rows; neither shape was checked against a real run. `comparison` is `agree` only when both ran and every table's count matched. Raw tables stay with `esedb_query`.
- **Joins.** The backend resolves application and user ids through `SruDbIdMapTable`; an id left unresolved stays in its row (`*_resolved: false`) and is counted (`unresolved_ids`). A network profile name needs the `SOFTWARE` hive, else the row says why it is unresolved.
- **Times.** A row's time is its end; `interval_seconds_since_previous_row_time` is the gap to the table's previous row time, not a measured interval. Each table means its own thing (`time_semantics`): never add, average or compare counters across tables. Units are the column name's, else `not stated by the backend`.
- **State.** `database.state` is the ESE header's: only a clean shutdown is complete; a dirty one with no log beside it is `partial`. Nothing is replayed here.
- **Bytes are not exfiltration.** A counter gives no remote endpoint, content or process instance: "the application was accounted N bytes sent on interface X in this interval" is the claim; "data was exfiltrated" needs named corroboration (network or proxy records, firewall logs, process creation, file access).
- **Retention and gaps.** Take each table's `retained_interval` and say it. An unreadable database, an unresolved id or a missing recent row is not zero activity.
- Sensitive output: paths, user and profile names pass the boundary (a secret-shaped text becomes a marker with its length). Describe a found secret by where it sits, its kind, length and what it grants, never its value, a fragment or a digest.

Shows: resource use accounted to an application and a user context in an interval. Does not show: who used the machine, what data moved or where, that a program ran to completion, or that a program without a row did not run. Record: per figure the table, `source_row`, `backend`, `time_raw`, the app id and name, SID, profile id, the unit.
