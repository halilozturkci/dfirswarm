---
id: execution/srum
title: SRUM resource accounting and its limits
when: You need an application's byte counts, CPU or network figures from SRUDB.dat, or its limits.
needs: [execution/esedb]
tools: [esedb_query]
requires_host: []
---

Use when you interpret rows of the System Resource Usage Monitor database. Not for exporting the tables (`execution/esedb`, read it before you cite a row) or for deciding that data left (`execution/overview`).

- **Source.** `C:\Windows\System32\sru\SRUDB.dat` is an ESE database with several resource-accounting tables of different schemas and interval semantics. Collect it with the ESE log and checkpoint files in the same directory, keep the original set untouched, and do any recovery on a derivative you record.
- **Reading it.** `esedb_query` exports tables as text. It decodes nothing and joins nothing, and the pack has no SRUM join reader: the joins are yours.
- **Joins.** An application or user column is an id into the id-map table (`SruDbIdMapTable`): resolve it there, not from the table you started in. The mapping's blob cells come back as the exporter wrote them: decode them offline, read only, and state how. Interface and profile ids need the matching table or a system artefact (`registry/overview`) before they name a network.
- **Times.** Each table has its own interval and its own meaning for a time cell, and the exporter's text form of a time and its zone are what it printed: keep the raw cell and establish the clock from the schema before converting (`registry/clock`). Do not average, sum or compare across tables without saying which counters you add.
- **Bytes are not exfiltration.** A counter gives no remote endpoint, content or process instance. "The application was accounted N bytes sent on interface X in this interval" is the claim; "data was exfiltrated" needs named corroboration: network or proxy records, firewall logs, process-creation records, file-access evidence.
- **Retention and gaps.** Assume no retention period and no write cadence: take the retained interval from each table (earliest and latest time) and say it. Delayed commits, configuration, shutdown, maintenance and the acquisition time can leave gaps; an unreadable database, an unresolved mapping or a missing recent row is not zero activity.
- Sensitive output: run `esedb_query` as a job with `secret_output: true`; what it withholds is in `execution/esedb`.

Shows: resource use the system accounted to an application and a user context in an interval. Does not show: who used the machine, what data moved or where it went, that a program ran to completion, which process instance produced a row, or that a program without a row did not run. Record: for each figure, the table, `_row`, raw time cell, application id and resolved name, SID, interface or profile id, the unit and the counter's meaning in that table.
