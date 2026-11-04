---
id: security/gatekeeper-xprotect
title: Quarantine, Gatekeeper and XProtect evidence
when: A question is whether a file was downloaded, quarantined, signed, notarised or scanned.
needs: []
tools: [plist_read, sqlite_query, timestamp_decode]
requires_host: []
---

Use when an answer turns on how a file or application reached the Mac and what the system's download checks recorded. Not for persistence (`persistence/mechanisms`) or for judging whether a file is malicious.

**Where it is recorded.** Four places, each only if the acquisition kept it:
- The `com.apple.quarantine` extended attribute on the file, a text value of flags, a time, the downloading application and an event id. Extended attributes are present only if the acquisition kept them (`triage/system-profile`); no attribute is a statement that none was set.
- The quarantine events database in the user's `Library/Preferences` (`com.apple.LaunchServices.QuarantineEventsV2`), SQLite: read it with `sqlite_query` on a copy, with its sidecars, and take its schema from the file. Its times are expected to be Apple absolute seconds; confirm from the schema and with `timestamp_decode` before converting.
- Provenance metadata, on builds that write it, as a further attribute; its content is not decoded here.
- The code signature of the program and any notarisation ticket stapled to it, and the XProtect version files, property lists inside the bundle under a `CoreServices` directory (the location varies by build; look in `/System/Library` and `/Library/Apple/System/Library`): read with `plist_read`.

**Reading them.** The event id in the attribute ties a file to a row of the events database; match them, and keep the attribute's time and the row's apart. A row can outlive the file and a file can lose its attribute, so absence of one does not clear the other. The agent named is the application that wrote the flag, not the origin of the content; the URLs are what that application recorded.

**Limits.** A quarantine flag is not malicious: it marks a download by an application that sets it. A file with no flag did not necessarily come from this machine: it may arrive by a route that sets none, or the flag may have been removed or not kept. A signature structure present in the evidence shows how the file was signed, not that Gatekeeper accepted it: `spctl` and `codesign` on the examiner's Mac describe that Mac, and a notarisation check needs Apple's online service. XProtect's version shows what rules the Mac held at acquisition, not that a scan ran or matched. Scan and policy decisions may appear in the unified log if retained (`logs/unified`).

Shows: that a download was recorded, by which application, with the times the records hold. Does not show: that the file was opened or run, that it is safe or malicious, or that a missing flag means local origin.
Record: file path and volume, attribute text (as the acquisition kept it), event id, database row and schema, times raw and converted, XProtect version, what was not kept.
Sensitive output: download URLs, origin URLs and sender names can carry tokens or personal data. Run a database read as a job with `secret_output: true` when the values matter; cite the row, never a copied URL or token.
