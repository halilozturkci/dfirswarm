---
id: logs/carving
title: Running and citing an evtx_carve sweep
when: You run evtx_carve over a blob, or quote a record it carved.
needs: [logs/recovery]
tools: [evtx_carve]
requires_host: []
---

Use when you sweep with `evtx_carve` or cite what it returned. Not for choosing the source to sweep (`logs/recovery`).

- **Signatures.** An `ElfChnk` signature is a candidate. The 128 bytes after it must pass a header check (header size 0x80, record offsets inside the 64 KiB, first record not after the last), because python-evtx accepts garbage. A failing one is a problem line, counted in `candidates` and `signatures_rejected`, never as a chunk.
- **Bounds.** `chunk_limit` (chunks parsed) and `candidate_limit` (places the magic was found) bound one call, not the result. When a call stops, `resume_start` is the offset to pass as `start`; `max_bytes` counts from `start`. Each continuation is its own job with its own tool-output file: collect `all_results` and `all_problems` from each. Read `range_requested` against `range_examined`: `sweep_complete` says the range was swept, not that every record that ever existed came back.
- **Rows.** `records` is a page of `limit` without XML unless `with_xml`; every match with its whole XML is in `all_results`. A repeated EventData name is a list.
- **Citing a record.** The source object, the byte offsets of the chunk (`chunk_offset`) and record (`record_offset`), its own claimed `computer`, `channel` and `provider`, `record_id`, `time_created` (the XML's SystemTime; a carved record has no header FILETIME) and `chunk_verified`. Keep the whole XML. The channel to cite is the one the record names, not the file it was found in; a pagefile or unallocated hit has no file. A computer name that is not the machine you examine is a finding to explain (a log viewed remotely, forwarded events, a copied image), not to overwrite.
- **Checksums.** `chunks_checksum_ok` counts chunks whose own checksums hold: internally consistent, not authentic, since a copied or altered chunk can verify. A chunk that fails may hold sound records; say which kind you quote. A record with missing fields stays partial.
- **Copies.** The same record can be carved from several copies of a chunk written at different times: compare channel, computer, record id and content, report each offset, count one event. Mixed generations break any simple order (`logs/coverage`).

Shows: a record's own fields at an offset of the source you swept. Does not show: which file it belonged to, its authenticity, or what the log held in total. Record: source, `range_examined`, counts (`chunks_found`, `chunks_checksum_ok`, `signatures_rejected`, `problem_count`), `sweep_complete`, and each cited offset.
Sensitive output: carved records hold command lines and arguments, and a pagefile or memory image can hold records of any process; run `evtx_carve` as a job with `secret_output: true` when they may.
