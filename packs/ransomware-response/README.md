# Ransomware Response Pack

Evidence-led ransomware examination. Its five tools return candidates, measurements and counts; what a
candidate shows has to be validated before anyone acts on it.

Depends on the Computer Forensics Base Pack. It does not repeat the intrusion
work: the Windows, Linux, network and memory packs do that, and this one says
where in the work each belongs. Where a skill names a tool of another pack, it
says "if that pack is loaded" and asks you to check the run's tool inventory.

## What it carries

**Twenty-two skills**: seven decision leaves, each a question of a case, ten
second-level leaves they point to ("only if X"), four method leaves that the router and the index
name (`intrusion/entry-and-spread`, `recovery/preserve-and-restore`, `platforms/esxi-hypervisors`, `platforms/nas-storage`),
and the router `ransomware/router` (at most 400 tokens; the prompt shows this one line for the pack when the run's index is over its budget, and it names every leaf); every leaf is at most 800 tokens.
`scope/first-hour` (`scope/triage-tools`, `scope/phase-timeline`),
`exfil/before-encryption` (`exfil/measure-and-claims`),
`encryptor/traces` (`encryptor/windows-evidence`, `encryptor/samples-and-notes`),
`encryptor/destroyed-backups` (`encryptor/backup-infrastructure`),
`identify/family` (`identify/samples-and-decryptors`),
`recovery/what-is-possible` (`recovery/routes-and-decryptors`),
`reporting/for-regulators` (`reporting/notification-register`,
`reporting/conclusions-and-controls`).

**Five tools.** `ransomware_scope_report` takes sealed outputs by reference (censuses,
extent and recovery outputs, timelines, a recipe's coverage) and reports scope per host
with denominators, assessed against unassessed bytes, candidate against validated
findings and a machine-readable coverage statement. A host with no census is
`unknown` and nothing is extrapolated to it; no estate-wide percentage is stated.
`recovery_validate` checks a recovery output that was produced
separately, against the original ciphertext and the decryptor's recorded provenance:
the structure of each file's format, a comparison with known originals, the
unrecovered ranges, and a verdict of one of four words (`matches_known_original`,
`structurally_valid`, `unrecovered`, `inconclusive`). It never runs a decryptor or
anything from the evidence, and an exit code is not evidence. `encryption_extent` measures where, in named files or in the candidates
of an `encrypted_survey` census given by reference, windows of bytes read as high
entropy, under a policy the caller declares (`sampling` or `full`). It names the bytes it did
not inspect, checks the head and the end of a file against its format, compares with a
plaintext counterpart when one is given, and judges a supplied layout. Its
`high_entropy_fraction` is a share of the inspected bytes, never a percentage
encrypted, and an intermittent pattern is an observed block pattern, never a family.
`encrypted_survey` identifies candidate files using extension and
entropy heuristics, samples selected windows and tails of the first candidates,
and groups filesystem modification times by hour. These results guide the
examination; they do not establish how much was encrypted, whether a file is
recoverable, an encryption window or a family. Files it did not match, could not
measure or could not read have buckets of their own, and a census of every entry
is written whole. `ransom_note_scan` finds files whose names look like ransom
notes and locates what is in them (identifier-like strings, addresses, wallets) by
byte offset without printing them: it is a candidate inventory, a name match is not
a confirmed note, and its values go only to a sealed job file
(`write_values: true` in a job run with `secret_output: true`). It also groups notes by
template similarity, computed on the text with every located value replaced by its kind,
so that no group follows a withheld value; a group is an observation about text, not
about an author.

**One goal template**: `ransomware-case.md`. Its checks require every question to
be answered under its heading, a timeline in UTC, an `Exfiltration conclusion:` line
in answer 2 (established, partial, bounded negative or not determinable) and the
harness's answer checks. Whether a conclusion is supported, and whether the position
on adversary access has reasons, is for the critic's `attest` or `dispute`, not for
a pattern match.

## How the work goes

Containment, preservation, impact assessment and notification assessment proceed in
parallel, according to ongoing harm and how fast the evidence goes. Reconstruct
initial access, staging, possible exfiltration, recovery impairment, encryption and
impact without assuming that every phase occurred or that their order was fixed.

And preserve before you restore. Every hour of restoration changes the sources.

## Not in this pack

No family rules or reference data ship with it, no public-decryptor catalogue, and
no tool of its own for hypervisor or backup records. `yara` is declared for rules the
case supplies.

For hypervisors and network storage the pack carries the method, in the
`platforms/esxi-hypervisors` and `platforms/nas-storage` skills (and, for the backup
server, `encryptor/backup-infrastructure`): what to preserve, how to separate a
guest's compromise from the host's or the storage's, and why a snapshot is not an
independent backup. The artefacts themselves (virtual-machine configuration, disk and
snapshot chains, backup job records) are read by the virtualization-backup-forensics
pack when it is loaded; the skills point to its tools without depending on it.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/ransomware-response
    scripts/swarm.sh start --pack computer-forensics-base,windows-forensics,ransomware-response ...
