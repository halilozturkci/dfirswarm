---
id: sessions/objects
title: Exporting protocol objects with their provenance
when: You export files or other protocol objects from a capture with pcap_extract.
needs: []
tools: [pcap_extract]
requires_host: [tshark, tcpflow]
---

Use when you export objects (HTTP bodies, SMB files, TFTP, mail) from a capture with `pcap_extract`. Not for choosing what to reconstruct (`sessions/reconstruct`).

- Run as a job with `secret_output: true`, `out_dir` under `$OUT`. Objects, their names and request URIs can hold credentials. A token-shaped name is withheld as `withheld-NNNNNN`, a URI loses user-info and query values, and an object under 128 bytes has no digest; the real values exist only in `pcap-extract-values.jsonl` when you ask `write_values: true` in a job.
- The tool asks tshark for the installed version and export types and refuses an unlisted type by name. Read `receipt.json`, not the exit code: a pass can be `ok`, `failed`, `timed_out` or `not_attempted`, and zero objects, a failed pass and a negative are three different results.
- `index.tsv` ties an HTTP object to a frame only when its bytes equal exactly one listed response body: `matched_by_content` (frame, stream, time, endpoints). `ambiguous` lists the frames; `unmapped` makes no claim and does not show the object was absent from the capture. Other protocols are indexed and unmapped.
- `-Y` may not limit an export on every build. Check the build, then check one object you rely on against the capture.
- tshark is the only engine here: agreement with the recipe's listings is one program agreeing with itself. Use `tcpflow` where the object matters.
- Open objects only with trusted parsers in quarantine.

Shows: files tshark exported, their size and digest, and a frame for an exact content match. Does not show: that the endpoint received or opened a file. Record: capture hash, tshark version, receipt, frame and stream, object hash (never a credential's).
