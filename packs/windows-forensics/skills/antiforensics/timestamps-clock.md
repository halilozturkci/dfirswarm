---
id: antiforensics/timestamps-clock
title: Timestamp manipulation and clock changes
when: File times disagree with other records, or the system clock may have been moved.
needs: [antiforensics/traces]
tools: [mft_records, usn_journal, evtx_query]
requires_host: []
---

Use when file times disagree with other records or the clock may have moved. Not for how the two NTFS time sets differ in ordinary use (`filesystem/timestamps`).

- `mft_records` returns the `$STANDARD_INFORMATION` and `$FILE_NAME` times side by side (raw FILETIME and ISO UTC); `timestomp_only` keeps records where they disagree. Its `si_` flags are indicators, and `filesystem/timestamps` lists the ordinary causes.
- Compare the raw values with independent records for the same file reference and sequence: `usn_journal` records, event logs, Prefetch, application records, another copy of the file, allowing for copying, restoration, extraction and clock error.
- A record with `structural_errors`, or an unresolved `$ATTRIBUTE_LIST`, is not compared as if it were whole. This pack decodes no `$LogFile`: say it was not examined and do not offer it as a clock (`filesystem/journals`).
- A clock change: Security 4616, where auditing records it, gives the previous and new time and the process (`evtx_query`). It makes times in the affected interval uncertain, not every wall-clock value unusable. Record before and after, the process and account, and the interval; then say which sources use the system clock (event times, file times written then) and which another (an external time source, another host, a hypervisor host).
- Event record ids, USNs and sequence numbers order records inside their own source and generation; they are not a common clock between sources.
- Alternatives to deliberate action: time synchronisation, a guest-integration service, manual correction, a zone or daylight-saving change (`registry/clock`).

Shows: a disagreement between sources, or a recorded clock change, at a stated place. Does not show: that a time was manipulated, by whom, or what the true time was. Record: the raw values from each source, the independent records compared, the interval of any clock change.

Sensitive output: `mft_records` with `with_resident` and `evtx_query` can return file content and command lines; run them as jobs (`secret_output: true`).
