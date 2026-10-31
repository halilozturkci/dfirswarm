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
