---
id: sessions/objects
title: Exporting protocol objects with their provenance
when: You export files or other protocol objects from a capture with pcap_extract.
needs: []
tools: [pcap_extract]
requires_host: [tshark, tcpflow]
---

Use when you export objects (HTTP bodies, SMB files, TFTP, mail) from a capture with `pcap_extract`. Not for choosing what to reconstruct (`sessions/reconstruct`).

- Run as a job with `secret_output: true`, `out_dir` under `$OUT`. Objects, their names and request URIs can hold credentials. A name that is token-shaped or carries a query string (Wireshark names an HTTP object after the end of its request target) is withheld as `withheld-NNNNNN`, with the real name always in `withheld-names.jsonl` of the output directory (0600); a printed request URI loses user-info and query values; an object under 128 bytes has no digest. The rule is by shape, so a name that is a hash, a GUID or a UUID is withheld too although it is no secret: its real name is in `withheld-names.jsonl`, and `write_values: true` in a job also writes the whole URIs to `pcap-extract-values.jsonl`. Withheld rows come after the readable ones, in content order: their position says nothing about their names.
- The tool asks tshark for the installed version, export types and (for the frame listing) fields, and refuses an unlisted type by name. Exit 0 means the engine ran: read `status`, `receipt.json` and `association_pass` (`fields_missing` names what the build lacks): a pass can be `ok`, `failed`, `timed_out` or `not_attempted`, and zero objects, a failed pass and a negative are three different results. `ftp-data` is exported by default where the build lists it.
- `index.tsv` ties an HTTP object to a frame only when its bytes equal exactly one listed response body: `matched_by_content` (frame, stream, time, endpoints). `ambiguous` lists the frames; `unmapped` makes no claim and does not show the object was absent from the capture. Other protocols are indexed and unmapped.
- `display_filter` reaches the export passes only, is not echoed, and may not limit an export on every build: check one object you rely on against the capture. `decryption_secrets_blocks` above 0 means tshark applied keys the pcapng carries, so objects can be decrypted content.
- tshark is the only engine here: agreement with the recipe's listings is one program agreeing with itself. Use `tcpflow` where the object matters.
- Open objects only with trusted parsers in quarantine.

Shows: files tshark exported, their size and digest, and a frame for an exact content match. Does not show: that the endpoint received or opened a file. Record: capture hash, tshark version, receipt, frame and stream, object hash (never a credential's).
