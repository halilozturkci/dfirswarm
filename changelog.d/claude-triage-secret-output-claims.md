### Fixed: triage-collection says what its secret-output check does

The six triage tool manifests and the README gave, as the reason to run the tools
as `secret_output` jobs, that "the tool cannot see whether the job was run so".
That has been false since the tools began reading `SECRET_OUTPUT` (`secret_job()`):
they say now that withholding by shape applies in every call and that
`write_values: true` is refused unless the job runs as secret output, which the
tool checks. A test fails if the old sentence comes back, and checks the
behaviour: `write_values` in a job is refused without `SECRET_OUTPUT=1` and
accepted with it, for all six tools. No tool changed.
