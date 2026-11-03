### Fixed: harness

The rival-area check (`rival_area_uncovered`) runs for every answer review. It
used to run only when a review gave `reproduced_at`, so a review that gave no
locator and no derivation passed where one that supplied more was capped, and
an agent could pass by dropping review metadata. Without locators the check
now follows the inputs the answer's support reaches (the answer's refs, the
refs of the entries it cites, and the derivation's inputs); with them it follows
the located objects, as before. The same answer gets the same verdict whatever
the review gives. The warning `no_locator_or_derivation` stays a warning.

### Added: harness

`swarm.sh package <id> --with-sessions` carries the agents' sessions
(`.pi-sessions/`) for an internal handover: regular files only, copied at a
cutoff, every recorded sensitive value replaced by its keyed id, in one
lossless archive (`sessions/sessions.tar.gz`) with a manifest (each file's
size and sha256 before and after masking, the masked count, the cutoff, where
each file goes back, and the files that changed while they were copied).
`verify` checks the archive and every member against the manifest. The flag is
refused together with `--redact`: a disclosure copy never carries sessions.
Masking removes the recorded sensitive values, not the evidence text the
models read.

### Removed: harness

The fanotify read-observation prototype (`scripts/job-observe.py`,
`scripts/job-observe.ts`, its two test files, the observe path of the job
service and the `SWARM_JOB_OBSERVE` switch) is deleted: it never ran in a
worker VM, and reads within a declared scope are not observed. Custody's "not
observed" is the final word, and `job_started` keeps `observed: "unknown"`, so
old and new runs read the same. The prototype stays in git history.

### Fixed: harness

An answer whose limitation cites an entry that rests on the kept output of a
failed job is no longer reported as having a defect: one role-aware rule
(`failedJobIsDefect`) decides it at the append and at the finish. A failed job
is the subject of a limitation, not a defect of the answer; an entry cited as
support that rests on a failed job is still refused at the append and flagged
by the answers check until the answer qualifies it.

### Fixed: harness

The regroup post lists each required question as the finish line's readiness
view sees it (no answer, a best candidate, a stale answer, a dispute, a
must-establish requirement not met), where it used to judge by three legacy
fields and listed one of four gaps. Each uncited object shows its lineage role
(case evidence, case-derived); a validation control or a tool reference is
listed apart, not as evidence no entry cites. Every list stays inside the
post's bound.

### Fixed: harness

`package --redact` works on a package that holds sealed read-only (0444) files:
a redacted file is written as a temporary file and renamed over the package's
copy, and the run's own files are never touched. A sensitive citation of a
directory (a job's output directory, in a package made `--with-outputs`)
withholds every file under it, each by its own keyed id, instead of failing
with EISDIR; a link or a device there is refused and named, never followed.
Sensitive digests are replaced in one pass over a text (the hex runs found
once, each digest looked up in a Set), so the cost grows with the text, not
with the number of digests: 50,000 digests over 20 MB take a fraction of a
CPU second.

### Changed: harness

The console says what an unmetered team is. The kickoff now records why a team
bills nothing per token (`unmetered_why`: `local` or `subscription`) in the
budget and run records. A subscription team is shown as "subscription · not
billed per token", with Pi's dollars marked as an estimate; a local team keeps
"no metered cost · local models"; a run whose record does not say why shows
"unmetered (reason not recorded)", never "free".

`stop` of a run found with nothing alive records what is known and no more:
the registry state is `ended` with `ended_by: "unknown"` and the time of the
trace's last line, and the trace holds one `run_ended` line, instead of a plain
`stopped` that said someone stopped it. A second stop keeps the record; a run
with anything alive still gets `stopped`. The console shows the run as over and
says on its agents tab that it ended without a stop, cause unknown.

`job_run` with a tool: the reply says why a place the agent gave is listed under
`not_written` when it was an empty directory given for reading. Such a
directory holds nothing to read, so it is taken as an output place
(`{OUT}/<name>`), and the reply's new `not_written_cause` line says that. The
comment on the mapping now states the rule the code keeps (a file of any size or
a directory with entries is read; an empty directory is an output place).

The shared growth helper of the timing tests (`tests/pack-re-timing.ts`, its Python
`growth` and `ladder`) no longer stops at the first round that looks linear, which
let a quadratic rule pass on one lucky round. It runs every round and judges
the median of each text; a ladder text that most rounds never reached has no
time and fails. The six files that use it keep the rule, and the nine-round
runs of one file are five.

The image build's downloads back off before a retry: after a 5xx, a timeout, a
dropped connection or a body that ended short the build waits 10 s and then 30 s
before the next attempt (`DFIRSWARM_FETCH_BACKOFF` shortens the waits;
`DFIRSWARM_FETCH_TIMEOUT` the read timeout), and a 4xx (a 404, a 403, a 429) is
the server's answer and is not retried. The build's message names each
attempt's cause and the wait.

### Fixed: docs

Three links in the belkactf6 use case that pointed one directory too high now
resolve (`improvement-plan.md` twice, `safety.md` once). A new node test,
`tests/markdown-links.test.ts`, resolves every relative link and reference
definition in the tracked Markdown (fixtures excepted; fenced blocks and code
spans are not read) and fails on any that is not a tracked file or directory,
naming it as file:line -> target. A Markdown change now selects it in
`scripts/test-select.ts`.
