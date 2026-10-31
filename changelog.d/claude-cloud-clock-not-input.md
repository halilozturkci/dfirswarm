### Fixed: cloud-forensics never blames the input for a stop by its own clock

When cloudtrail_parse's or ual_parse's `time_limit_seconds` ended the read before
any record was read (a slow runner, a large first file), the answer was `failed`
with "no CloudTrail event could be read from what was supplied" (ual_parse: "no
audit record could be read"), an exit code 1 and an `error` saying the data was
unreadable. It is now `partial`, as the `time_limit_seconds` description
promises: the `status_basis` begins with the clock and names the files read and
not attempted (and any that failed before the stop), there is no `error`, and the
exit code is 0. `failed` is given only when the clock did not stop the read.
signin_analyse's partial basis names the clock when the clock cut the read.
`tests/cloud-clock-inject.py` runs a tool with its clock already out, so the
tests no longer depend on how much a runner reads in a second.

The same rule holds for the tool's other limits. When `max_expanded_bytes`, or `max_record_bytes` (every record of a file larger than it, including the first-1000-rejects stop it causes), ended the read before any event or record was read, cloudtrail_parse, ual_parse and signin_analyse answered `failed` with "no ... could be read from what was supplied" and a first-rejects sentence saying the file "is not an export this tool reads". They now answer `partial` with a basis that names the limit and its value ("max_expanded_bytes (1024) stopped the read ... before any event; raise it; nothing was judged"), no `error`, exit 0, and `coverage.limit_stops` / `limit_stop` carry the same text; the first-rejects sentence is kept for rejects the limit did not cause.
