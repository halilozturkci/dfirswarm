# Ransomware Response Pack

Evidence-led ransomware examination. Its eight tools return candidates, measurements and counts; what a
candidate shows has to be validated before anyone acts on it.

Depends on the Computer Forensics Base Pack. It does not repeat the intrusion
work: the Windows, Linux, network and memory packs do that, and this one says
where in the work each belongs. Where a skill names a tool of another pack, it
says "if that pack is loaded" and asks you to check the run's tool inventory.

## What it carries

**Twenty-five skills**: seven decision leaves, each a question of a case, eleven
second-level leaves they point to ("only if X"), six more leaves that the router and the index
name (`intrusion/entry-and-spread`, `recovery/preserve-and-restore`, `platforms/esxi-hypervisors`, `platforms/nas-storage`, `impact/services-and-data`, `recovery/public-decryptors`),
and the router `ransomware/router` (at most 400 tokens; the prompt shows this one line for the pack when the run's index is over its budget, and it names every leaf); every leaf is at most 800 tokens.
`scope/first-hour` (`scope/triage-tools`, `scope/phase-timeline`),
`exfil/before-encryption` (`exfil/measure-and-claims`),
`encryptor/traces` (`encryptor/windows-evidence`, `encryptor/samples-and-notes`),
`encryptor/destroyed-backups` (`encryptor/backup-infrastructure`),
`identify/family` (`identify/samples-and-decryptors`),
`recovery/what-is-possible` (`recovery/routes-and-decryptors`),
`reporting/for-regulators` (`reporting/notification-register`,
`reporting/conclusions-and-controls`).

**Eight tools.** `backup_destruction_correlate` keeps five observations apart per host and
object (command seen, action attempted, reported outcome, inventory change, verified loss)
from the answers of other packs' tools given by reference, each versioned by its `parser`.
It copies no event text, reports a command with no change and a change with no command as
such, and never turns "a delete command ran" into "the backups are gone".
`ransomware_family_match` gives candidate families and variants for the extensions and ransom-note names an examination
observed (the note names come from the sealed values file of `ransom_note_scan`, run as a secret_output job), with the
reference features that matched, their strength and sources, the rule ids and versions of the note-text rules (`yara` is the
engine), contradictions, and `ambiguous` or `unidentified` when the evidence does not separate or support a family. Its
reference set is a dated, reviewed snapshot of seven families, each entry citing the public pages it comes from; a stale entry
is reported, a changed file is refused, no match does not mean that an unknown family is absent, and a family never
names an affiliate or an actor.
`decryptor_catalog` (its method is `recovery/public-decryptors`) is an offline metadata reader over a dated snapshot of five public decryptors (Avast's for Akira and Rhysida, the
Japan National Police Agency's for Phobos and 8Base, the No More Ransom listing of one for LockBit 3.0, and Security Research Labs' scripts
for Black Basta). For family and variant hypotheses and the prerequisites you hold it gives the publisher, the variants and period the
sources state, the prerequisites (a file pair, the machine the files were encrypted on, known plaintext) with whether each is met, the
limits, the approved source and the check date. An unknown family answers `no_entry_in_snapshot`, which is not "no decryptor exists"; the
tool fetches nothing, runs nothing, redistributes nothing, and the obtained-and-verified flag is only ever the caller's.
`ransomware_scope_report` takes sealed outputs by reference (censuses,
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

It ships a small dated snapshot of family features for `ransomware_family_match` (seven families, each entry citing public
pages, none naming an affiliate or an actor) and no rules for a sample's code; `decryptor_catalog` has a dated snapshot of five public decryptors and none of the decryptors
themselves. The pack has no tool of its own that reads hypervisor or backup records (`backup_destruction_correlate`
takes the answers of the other packs' readers by reference). `yara` is declared for rules the
case supplies.

For hypervisors and network storage the pack carries the method, in the
`platforms/esxi-hypervisors` and `platforms/nas-storage` skills (and, for the backup
server, `encryptor/backup-infrastructure`): what to preserve, how to separate a
guest's compromise from the host's or the storage's, and why a snapshot is not an
independent backup. The artefacts themselves (virtual-machine configuration, disk and
snapshot chains, backup job records) are read by the virtualization-backup-forensics
pack when it is loaded; the skills point to its tools without depending on it.

## A program that leaves a process behind

`ransomware_family_match` reports only what `yara` printed on a pipe. The pipe of a `yara` that has ended is read for at most one more second and 1 MiB and then let go (what still holds it is ended first), so a process it left
running does not hold the call, and a `yara` that exited is not reported as timed out. A process the shared process block had to end makes the answer `partial` (a line in
`partial_reasons`), because what it would still have printed is not in the hits; a host that cannot adopt orphans (not Linux, or the kernel refuses
`PR_SET_CHILD_SUBREAPER`) does not, and `program_group.unproven` says it. A call that ran `yara` carries `program_group` (`subreaper`, `left_behind`, `unproven`, `notes`).

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/ransomware-response
    scripts/swarm.sh start --pack computer-forensics-base,windows-forensics,ransomware-response ...
