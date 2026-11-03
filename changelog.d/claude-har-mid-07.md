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
