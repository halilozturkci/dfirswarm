### Added: ransomware-response has two platform leaves, `platforms/esxi-hypervisors` and `platforms/nas-storage`

Two method leaves of at most 800 tokens each. The ESXi leaf keeps the host, the
management plane, the guest and the datastore apart, lists what to preserve
(the version's support bundle, task and event records, authentication and shell
activity, machine configuration, virtual-disk descriptors, backing extents and
snapshot chains) and says not to consolidate a snapshot, power on, register or
migrate a machine, or reboot the host before the chain metadata is preserved.
The NAS leaf separates a client's writes, a compromised management plane and
replication of damaged data, lists the appliance records to preserve, and says
that imaging one RAID member is not a logical acquisition. Both route to the
virtualization pack's `virtualization_inventory`, `snapshot_chain_check` and
`backup_audit_normalise` only conditionally ("if the virtualization-backup-forensics
pack is loaded; check the run's tool inventory", `mentions:` only); no
dependency is added. `encryptor/backup-infrastructure` now points to the two
leaves for hypervisors and network storage instead of repeating them, and
`ransomware/router`, the index, the README and the `method_only` list name both.
Measured: the leaves are 719 and 634 tokens; the router, which names every leaf of the
pack once, went from 329 of 400 tokens to 396 with all the leaves this bundle adds, and the index
from 663 of 1,000 to 885.

### Added: ransomware-response has two more method leaves, `intrusion/entry-and-spread` and `recovery/preserve-and-restore`

Each is at most 800 tokens, named once by `ransomware/router` and the index, and `method_only` in
the pack manifest. `intrusion/entry-and-spread` reconstructs initial access, persistence and
deployment as a graph of observed edges, correlates VPN, identity, mail, endpoint-detection,
service, task, remote-management and cloud-audit records, keeps the alternative routes and a
bounded observation window, and reproduces no exploit; it names the readers of the Windows, Linux,
cloud and network packs only conditionally (`mentions:` and "if the pack is loaded; check the
run's tool inventory"). `recovery/preserve-and-restore` states the minimum preservation package
before a rebuild, consolidation, repair, decryption or reconnection, the emergency exceptions and
the evidence each loses, isolated recovery tests, identity remediation, clean-build decisions and
authorised acceptance. Neither repeats a sentence of `scope/phase-timeline`, `scope/first-hour` or
`recovery/what-is-possible`; a test holds that.

### Added: ransomware-response has a third tool, `encryption_extent`

It measures where, in named files or in the candidate rows of an `encrypted_survey` census given by
reference (the receipt's `parser` must be `encrypted_survey/3`; another is refused by name), windows of
bytes read as high entropy, under a policy the caller declares (`sampling` or `full`). It reports per file
the bytes inspected and the uninspected ranges, `high_entropy_fraction` (a share of the inspected bytes,
never a percentage encrypted), the high-entropy runs, an observed block pattern when runs recur at equal
spacing, the magic, footer and container directory of the file's format as booleans, a comparison with a
plaintext counterpart, and findings against a layout the caller supplies. It prints no byte of a file. The
whole profile is a JSON Lines file that a rerun never replaces. The entropy function is `encrypted_survey`'s
(a test holds the two sources equal); the shared PLACE, PAGE, STOP, WITHHOLDING, NAMES and BACKSTOP blocks and
`LosslessPage` are copied byte for byte. The default threshold is 7.5 (this pack's; the reverse-engineering
pack's 7.2 finds packed regions of executables). `encryptor/samples-and-notes` and `recovery/what-is-possible`
name it. Measured: a full scan of a 64 MiB file at window 64 took 19.1 s at 23 MB resident and wrote 106,687,821
bytes of profile; a 64 MiB window takes about 2.3 s, so a window is not started when the time left is less
than 60 ns per byte of it. The carrier tests for the names, the stop block and the withholding block list it.

### Changed: ransomware-response `scope/triage-tools` hands its Names paragraph to `scope/triage-tools-names` and gains the survey-versus-extent rule

The Names paragraph (what the survey and the scan withhold from a path, and the printed and withheld
shapes) moved word for word to a second-level leaf, `scope/triage-tools-names`, which `scope/triage-tools`
points to in the text ("Only if ..."). A sentence-by-sentence register of the old leaf against the two new
ones shows 31 of 31 sentences in place and none lost; the sentence that says to run the survey with
`secret_output: true` where key material is expected stays in `scope/triage-tools`. `scope/triage-tools`
now says when to use `encrypted_survey` (which files look encrypted, and their tails) and when
`encryption_extent` (where in a file windows read high, and the ranges left unread), and that neither one
alone shows that a file was encrypted. Measured: `scope/triage-tools` 800 to 713 tokens, the new leaf 370;
at the head of this bundle the router is 396 of 400 tokens and the index 885 of 1,000 (the harness's own estimator, 24 entries).

### Added: ransomware-response has a fourth tool, `recovery_validate`

It checks a recovery output that was produced separately against the original ciphertext and the decryptor's
provenance, which it records as given and does not use. It never runs a decryptor or anything from the
evidence and never unpacks an archive. Per file it reports the size and sha256 (not printed for a file that looks
like a credential file), the structure of its format (the ZIP central directory walked against the end record,
the PDF startxref target, the PNG and JPEG markers, the SQLite header and a read-only integrity check on a copy
under the output directory, the decodability of text), a comparison with a known original (a hash per file or a
sha256sum list), the unrecovered ranges (whole granules still equal to the ciphertext or all zero, every one in
a profile file), and a verdict of exactly one of `matches_known_original`, `structurally_valid`, `unrecovered`,
`inconclusive`. `recovery/routes-and-decryptors` names it and is no longer `method_only`. Measured: a 64 MiB file whose
512-byte granules alternate between zeros and random bytes (65,536 ranges) took 1.4 s at 25 MB resident and wrote
6,609,067 bytes of profile; a random 256 MiB file took 0.6 s.

### Added: ransomware-response has a fifth tool, `ransomware_scope_report`

It takes sealed outputs by reference (censuses of `encrypted_survey`, the profiles of `encryption_extent` and
`recovery_validate`, timelines of host, time and kind events, a recipe's `coverage.json`), each versioned by the
`parser` of its receipt (another version is refused by name), and reports per host the scope with denominators,
the bytes inspected against the bytes in the census, candidate against validated findings and the coverage
statements, and for all hosts a machine-readable coverage statement. A host with no census is `unknown`; a host
with two censuses is a `conflict` and is not added to the totals; no figure is extrapolated and no estate-wide
percentage is stated. Aggregation streams into a SQLite index under the output directory (sums only, no row of
an input) in bounded memory; the answer is paged and the whole is in files. Measured: a census of 10,000,000
rows (261 bytes each) was read in 76 s at 24 MB resident; a deep-tier suite asserts the bound.
`scope/phase-timeline` and `reporting/conclusions-and-controls` name it and are no longer `method_only`. The
carrier tests list the new tool, and `tests/node-tests.deep` lists its deep suite.

### Added: ransomware-response `ransom_note_scan` groups notes by template similarity (parser ransom_note_scan/4)

Notes are grouped by the overlap of the 3-token shingles of their text after every located indicator span has
been replaced by its kind, so that no membership, count or order of a group follows a withheld value. Per group
the answer gives the member note ids and directories (the first 20 in the row, every one in
`template_group_members`), the copies, and the earliest and latest modification time as observations; no note,
occurrence or exact-duplicate group is dropped, and the sealed values file is unchanged. Only the first 65,536
characters of a note are compared, a note is held as its 128 smallest shingle hashes (the similarity is exact when
two notes together hold at most 128 distinct shingles, otherwise an estimate with a standard error near 0.035 at
0.8), and the grouping holds at most 50,000 notes: more are counted and make the answer partial. The parameter
`template_threshold` (default 0.8, 0.5 to 1.0) sets the similarity at which two notes are one template. The
parser changes from `ransom_note_scan/3` to `/4`; a reader of that output has to accept `/4` and refuse any other
version by name. The tool version goes from 9 to 10.

### Added: ransomware-response has a leaf for services and data, `impact/services-and-data`

It keeps confidentiality, integrity and availability effects apart from file counts, covers services with their
dependencies, safety consequences and outage intervals, datasets and populations, and marks every figure as
estimated, tested or confirmed. It names `ransomware_scope_report` and the fields it writes (`coverage_statement`,
`assessed_against_unassessed`, `candidate_against_validated`, `estate_wide_percentage`, the scopes `unknown` and
`conflict`), and says that no tool decides materiality. A test holds that each field it names is one the tool
writes. The router, the index and the README name it; it is not `method_only` because it names a tool of the pack.

### Fixed: ransomware-response new tools, after verification

`ransomware_scope_report` read a line over 1 MiB in a loop with no clock: a multi-terabyte sparse file with no
newline ran far past `max_seconds`. The loop now checks the clock between reads and the input is reported as cut
by it. Byte and run sums are held at 2^50 per key and input (a sum that reaches it is shown as the cap and makes
the answer partial) so that no sum overflows the index. The timeline index keeps the first 100,000 distinct
(host, kind) pairs and counts later kinds under one kind, saying so. `encryption_extent` and `recovery_validate`:
`time_limit.reached` is true when the clock ended a file; a counterpart or ciphertext that could not be compared
(missing, not a regular file, unreadable, another size) makes the answer partial and is named; and
`possible_zip_bomb` is true when the directory declares data in no compressed bytes. The ESXi leaf says that
`backup_audit_normalise` reads Proxmox task logs and caller-mapped exports only. Every other read loop of the three
tools and of `ransom_note_scan`'s grouping was checked for a clock: they have one per row, chunk, window or entry.
