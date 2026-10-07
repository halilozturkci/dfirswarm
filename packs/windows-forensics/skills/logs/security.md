---
id: logs/security
title: Reading an event log with evtx_query
when: You are about to read, filter or quote records from an .evtx file.
needs: []
tools: [evtx_query]
requires_host: [evtxexport, EvtxECmd, dotnet, MFTECmd, RECmd]
---

Use when you query an `.evtx` file. Not for what an id means (`logs/events`) or what a missing event shows (`logs/coverage`).

Take the channel from the record, not the file name; extract files with `filesystem/extract`.

- **What a run says.** `records_examined`, `events_matched` and `parse_errors` are separate counts; a record it cannot read is an error row, never a match. `status: partial` is a parse error, a chunk chain not enumerated to its end, or a file shorter than its header declares (`chunks_declared` against `chunks_read`, `bytes_expected` against `file_bytes`). A cut-short log is not a log with no records.
- **Rows.** `record_offset`, `chunk_offset`, the EventRecordID, `timestamp` (the XML's SystemTime), `record_filetime` and `record_time_utc` (the header's). `data` holds EventData and UserData fields, a repeated name as a list.
- **Filters.** `event_ids`, `contains` (case-insensitive, on the XML), `start_record`/`end_record`, `start_time`/`end_time`: ISO 8601, a date is the whole day, `Z` or an offset like `+03:00` is applied, no zone is UTC. A word, a malformed time or a reversed range is refused. A record with no SystemTime cannot be placed: under a time filter it is left out, counted in `events_without_time_excluded`, and the run is partial.
- **Results.** `limit` is an inline page; every match with its whole XML is in `result_file` (JSON Lines). An earlier result is never replaced: a taken name gets `-2`, `-3` and `result_file_requested` says what you asked for. Cite the file named.
- **Time.** SystemTime and the header FILETIME are UTC from the writing machine's clock, uncorrected for a clock that was wrong or changed. They agree beyond microsecond rounding (python-evtx gives six fractional digits, `record_time_utc` seven); a larger difference is reported with both values and no cause. Zone rules: `registry/clock`.
- **Identify, then read.** Provider, channel, id and `Version` identify an event; Subject is the requester, Target the account acted on. Read `logs/events` only if you need an id's meaning or a logon type.
- **A second reader.** For a record a finding rests on, and whenever `parse_errors` is not zero, read the file with `evtxexport` or `EvtxECmd` (its maps normalise payload differences). `dotnet` is the runtime MFTECmd, EvtxECmd and RECmd run on. All are optional: check the tool inventory, else say the cross-check was not made. A record only one reader opens is a reader limit, not a property of the log.

Shows: that a provider wrote these fields at that time on that clock. Does not show: who was at a keyboard, that an operation completed unless the record carries its outcome, or that the file is whole and unaltered (`antiforensics/traces`). What an operator typed is `logs/powershell`; rule-based review is `logs/hunting`. Record: file, channel, record id, `record_offset`, status and counts, reader and version.
Sensitive output: `evtx_query` returns command lines and typed text; run it as a job with `secret_output: true` when the log may hold a secret.
