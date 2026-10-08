---
id: filesystem/ads
title: Named NTFS data streams
when: You need to enumerate, extract or date alternate data streams, or assess execution from one.
needs: [filesystem/mft]
tools: [mft_records, extract_stream, usn_journal, file_type]
requires_host: [fls, istat]
---

Use when a named `$DATA` attribute may hold something. Not for the record itself (`filesystem/mft`) or download marks (`browser/downloads`).

- A file can have an empty default stream and a named one full of data: a listing size of zero says nothing about the streams behind it.
- Enumerate from metadata, not from a colon (`fls` prints a colon after every inode). Ask `mft_records` with `streams_only`: each record shows the stream `name`, `resident`, sizes, the attribute `instance` and the record's `ads` list. Confirm with `istat`, which prints attributes and their ids. A record with `has_attribute_list` may keep streams in extension records (join them, `filesystem/mft`); a deleted record can still carry streams (check `in_use`, `sequence`).
- Many streams are routine: `Zone.Identifier`, sync clients, security products, the shell, and `$UsnJrnl:$J` itself. Read the content before deciding what one is.
- Extract by address `<entry>-128-<instance>`; a bare entry extracts the default stream. `extract_stream` takes the image, the address, the offset in sectors (`evidence/imaging`) and an `output` under your own `work/<your id>/...`. It never overwrites; it answers with the address as parsed, size, sha256, exit status and a stderr file. A failed read leaves `<output>.partial` (`partial_file`, `status: failed`) and is not an extraction; a rerun keeps earlier files as `.2`, `.3`. Record source (entry, sequence, path), stream name, address, offset, output, size, sha256.
- `file_type` says what the first bytes are and whether the extension agrees; a mismatch does not by itself show concealment, and byte identity with a legitimate executable does not make its presence benign.
- A stream has no timestamps and the file's times may not date it. `usn_journal` can: `STREAM_CHANGE` and the `NAMED_DATA_` reasons on the file's reference and sequence, within the journal's window (`filesystem/journals`).
- A file named after a reserved DOS device (`LPT1`, `COM1`) can defeat path-based access through the Windows API; a filesystem parser reads the record. Report the stored name, and do not take a failed path interface for unreachable bytes.
- To say a program ran from a stream, validate its bytes and find an execution record that names the stream or its path (`execution/prefetch`, `execution/overview`). An odd Prefetch file name or an empty default stream is a lead, not a signature.

Shows: this record carried a named stream with these bytes. Does not show: who created it, that its carrier was the intended one, that the content was used or ran. Record: the mapping above and the count of `$MFT` records read with their `status`: a stream whose record was reused, or sits in an unresolved extension record, would not appear.
Sensitive output: a stream can hold a secret; extract in a job with `secret_output: true`. The tool never prints the bytes, and its size and sha256 are the custody record.
