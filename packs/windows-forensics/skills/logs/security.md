---
id: logs/security
title: Reading .evtx
when: Read, filter or quote .evtx records.
needs: []
tools: [evtx_query]
requires_host: [evtxexport, EvtxECmd, dotnet, MFTECmd, RECmd]
---

Use when you query an `.evtx` file. Not for what an id means (`logs/events`) or what a missing event shows (`logs/coverage`).

Take the channel from the record, not the file name.

- **What a run says.** `records_examined`, `events_matched` and `parse_errors` are separate counts; a record it cannot read is an error row, never a match. `status: partial` is a parse error, a chunk chain not enumerated to its end, a file shorter than its header declares (`chunks_declared` against `chunks_read`, `bytes_expected` against `file_bytes`).
- **Rows.** `record_offset`, `chunk_offset`, the EventRecordID, `timestamp`, `record_filetime` and `record_time_utc` (the header's). `data` holds EventData and UserData fields, a repeated name as a list.
- **Filters.** `event_ids`, `contains` (case-insensitive, on the XML as printed: withheld text is not searched, so unmatched records with text withheld are counted in `contains_blind_records` and the run is partial), `start_record`/`end_record`, `start_time`/`end_time`: ISO 8601, a date is the whole day, an offset like `+03:00` is applied, no zone is UTC. A record with no SystemTime is left out under a time filter, counted in `events_without_time_excluded`, and the run is partial.
- **Results.** `limit` is an inline page; every match with its XML is in `result_file`. A result is never replaced: a taken name gets `-2` and `result_file_requested` says what you asked for.
- **Time.** SystemTime and the header FILETIME are UTC from the writing machine's clock, as right as that clock; they agree to microsecond rounding, a larger difference is reported with both values, no cause. Event Viewer shows local time, so a screenshot's time is not the XML's. Zones: `registry/clock`.
- **Identify, then read.** Provider, channel, id and `Version` identify an event; Subject requests, Target is acted on. Read `logs/events` only if you need an id's meaning.
- **What the boundary hides.** A record with something secret-shaped in it has that text, often its whole `xml`, replaced: PowerShell/Operational 25% of records (4104), CodeIntegrity 33% (3089, a base64 `Hash`). Such a `partial` is a filtered log, not a damaged one; use the plain `data`.
- **A second reader.** For a record a finding rests on, and whenever `parse_errors` is not zero, read the file with `evtxexport` or `EvtxECmd` (`dotnet` runs it, MFTECmd and RECmd). All are optional: check the tool inventory, else say the cross-check was not made. A record only one reader opens is a reader limit, not a property of the log.

Shows: that a provider wrote these fields at that time on that clock. Does not show: who was at a keyboard, that an operation completed unless the record carries its outcome, or that the file is whole and unaltered (`antiforensics/traces`). What the intruder typed is `logs/powershell`; rule-based review is `logs/hunting`. Record: file, channel, record id, `record_offset`, status and counts, reader and version.
Sensitive output: `evtx_query` returns command lines and typed text; run it as a job with `secret_output: true` when the log may hold a secret. Describe a found secret by where it sits, its kind, length and what it grants, never its value, a fragment or a digest.
