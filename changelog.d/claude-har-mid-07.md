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
