---
id: browser/webcache
title: WebCache and legacy index.dat
when: The evidence holds WebCacheV01.dat or Internet Explorer index.dat files.
needs: [browser/artefacts]
tools: [esedb_query]
requires_host: [esedbexport, msiecfexport]
---

Use when the evidence holds WebCacheV01.dat or legacy index.dat files. Not for current Chromium or Firefox history (`browser/artefacts`).

- `WebCacheV01.dat` is written by the Windows internet stack and its consumers; it is not a browser history file. `esedb_query` exports its tables with `esedbexport`; read `execution/esedb` only if you need the export mechanics or the answer's accounting (partial export, ambiguous table, withheld columns).
- `esedb_query` resolves no container. Find the Containers table, map the container id of the table you read to what it holds, and only then read a URL. Name the container and the record type before you call a host browsing; a host with no time-stamped visit-type record is a string.
- Rows come from the browser, from other components that use the same stack, and from background activity. A cache or WebCache row is not a visit.
- ESE logs are neither read nor replayed: a database in a dirty state may lack its newest rows; say so.
- Older Internet Explorer installations keep history, cache and cookie indexes in `index.dat` files under the profile's legacy folders. Neither WebCache export nor the history queries read them. Where the host carries `msiecfexport` (optional), read them with it; an index record is a URL the cache listed, not a visit by a person. Without it, say the legacy files were not read: that is not an empty history.

Shows: that a component of the Windows internet stack stored or fetched that URL, with the container's record type and times. Does not show: a visit by a person, a download, or where a time cell's zone comes from until the schema says. Record: database digest, export status, container, record type, raw time cell.

Sensitive output: URLs here can carry tokens; run `esedb_query` as a job (`secret_output: true`). Its own withholding is in `execution/esedb`.
