---
id: browser/downloads
title: Download provenance
when: Establish where a downloaded file came from and whether the transfer finished.
needs: [browser/artefacts]
tools: [browser_history]
requires_host: []
---

Use when you establish where a file came from and whether its download finished. Not for the visit history itself (`browser/artefacts`). Open `browser/artefacts` first for the copy and WAL fields.

Four things must agree before a provenance sentence is written: the browser's record, its URL chain, the file, and the file's `Zone.Identifier`.

- Record. `chrome_downloads` returns id, target path, `tab_url` (the page the download started from, not necessarily the URL it came from), total and received bytes, and raw and UTC start and end. State, danger type, interrupt reason, referrer and the URL chain are in other columns or tables (Chromium keeps the chain in `downloads_url_chains`, if this version has it): read them with `sql`. `firefox_downloads` returns the download annotations as stored; bring the page URL in through its place id. Compare received with total bytes and the end time: an interrupted transfer is not a completed one.
- File. The target path, whether the file is still there, its size and hashes against the record. A record is not the file now on disk (`filesystem/mft` when the file is gone).
- `Zone.Identifier` (`filesystem/ads`). The zone and, where the writer recorded them, a referrer or host URL. Mail clients and archivers write it too, so presence shows that some writer marked the file, not that a browser fetched it. Absence proves little: the destination may not support streams, a copy may have dropped it, or it may have been removed.
- A staging directory of virtualisation software, a synchronised folder or a temp path says how the file arrived last. It neither excludes an earlier browser download nor names the origin. A URL string alone, in any source, is neither a visit nor download provenance (`browser/strings`).

Shows: the browser's account of a transfer. Does not show: that it finished, that the file is the one on disk now, that it was opened or run, or an origin that no record or stream names. Record: download id, URL chain (secrets withheld), state, bytes received and total, target path, Zone.Identifier content, the file's hash.

Sensitive output: URLs in a download row can carry tokens; `browser_history` withholds them as it does for visits (`browser/artefacts`).
