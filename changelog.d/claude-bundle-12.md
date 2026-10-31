### Changed: ransomware-response states how yara is pinned

The `yara` entry of the pack's `requires/host.json` no longer says that its
version is not pinned. On Linux the image installs it from the Debian snapshot
at the date in `images/debian-snapshot`, so the version is the one Debian 12
(bookworm) held on that date (4.2.3-4 at the time of writing); the apt line is
not edited, the snapshot pins it. Homebrew on macOS stays unpinned, and the
entry says so. `optional` and `redistributable` are unchanged.
`tests/recipe.test.sh` now refuses an apt entry that says its version is
unpinned and checks the yara entry. No image is rebuilt.

### Fixed: ransomware-response leaves no hidden temporary file from a stop between create and register

`ransom_note_scan` and `encrypted_survey` held no protection for the moment
between creating a page's (or the census's) temporary file and registering it
for the stop handler: a SIGTERM, SIGINT or SIGHUP there ended the tool with its
JSON answer but left `.ransom_note_scan-*`, page or census temporary files in
`$OUT`. Both `LosslessPage` copies and `encrypted_survey`'s `Census` now hold
the three stop signals for those steps and restore the old mask right after
(in a `finally`), so a held signal is delivered once the file is registered and
the handler removes it. Where `signal.pthread_sigmask` is missing the call is a
no-op. The shared STOP block is unchanged. New cases in
`tests/pack-ransomware-stop.test.ts` signal from inside `tempfile.mkstemp`, for
each page and for the census, with each of the three signals.

### Changed: ransomware-response manifests state the remaining residuals

No tool code changed; the two manifests now say what stays open, so that a
caller is not told more than is true:

- Start-up window (both tools): the stop handlers are installed when the module
  code reaches the stop block, so a stop signal in the first moments of the run
  (interpreter start, compiling the file, the module code above the block) can
  end the tool with no JSON answer. The early answer's status word is not
  stated here: it belongs to the shared stop text.
- `ransom_note_scan` lists five residual classes: the whole-file sha256 of a
  note of 128 bytes or more whose only variable part is a short identifier; UTF-16
  without a byte-order mark, found only when ASCII dominates; the value rule
  that withholds a name is a literal substring test; the name pattern's `help`
  alternative (2.0% of 600,000 real names); derived quantities (the length of
  an occurrence, its validation, counts per kind). It also says that a path
  holding more than 64 distinct 8-character windows makes the first pass match
  its note in full, which costs more of the first pass's time.
- `encrypted_survey` states the census's cost in its `census` parameter, by
  kind of row: about 0.3 to 0.5 KB per ordinary file, 0.6 to 0.8 KB per
  candidate with short paths, up to about 1.1 KB per candidate under long
  paths; plan for about 1 KB per entry on a tree of candidates (about 100 MB
  per 100,000 files), so that a caller can choose `census: false` for a large
  tree. `tests/pack-ransomware-census-size.test.ts` pins each range against
  trees the test builds (ordinary files, candidates, candidates under a path
  of about 150 characters).
- `ransom_note_scan`'s module docstring now carries the start-up caveat too.
- Stay stated as they were, and are now held by `tests/pack-ransomware-prose.test.ts`:
  the raw tail bytes (`tail_bytes` text and the two skill lines), and the job
  residuals (SIGKILL leaves the hidden temporary files; the job's timeout is
  not passed to the tool).

### Changed: ransomware-response points to the virtualization pack

The README's "Not in this pack" no longer says there is no examination method
for hypervisors or network storage: it says the pack carries the method
(`encryptor/backup-infrastructure`) and that the artefacts are read by the
virtualization-backup-forensics pack when it is loaded. The leaf says so
conditionally ("check the run's tool inventory") and lists
`virtualization_inventory`, `snapshot_chain_check` and `backup_audit_normalise`
under `mentions:`. It stays `method_only` (its reason now says the tools belong
to another pack and are only mentioned) and adds no dependency edge.
