# Ransomware Response Pack

Evidence-led ransomware examination. Its two tools return candidates; what a
candidate shows has to be validated before anyone acts on it.

Depends on the Computer Forensics Base Pack. It does not repeat the intrusion
work: the Windows, Linux, network and memory packs do that, and this one says
where in the work each belongs. Where a skill names a tool of another pack, it
says "if that pack is loaded" and asks you to check the run's tool inventory.

## What it carries

**Eighteen skills**: seven decision leaves, each a question of a case, ten
second-level leaves they point to ("only if X") and the router `ransomware/router` (at most 400 tokens; the prompt shows this one line for the pack when the run's index is over its budget, and it names every leaf); every leaf is at most 800 tokens.
`scope/first-hour` (`scope/triage-tools`, `scope/phase-timeline`),
`exfil/before-encryption` (`exfil/measure-and-claims`),
`encryptor/traces` (`encryptor/windows-evidence`, `encryptor/samples-and-notes`),
`encryptor/destroyed-backups` (`encryptor/backup-infrastructure`),
`identify/family` (`identify/samples-and-decryptors`),
`recovery/what-is-possible` (`recovery/routes-and-decryptors`),
`reporting/for-regulators` (`reporting/notification-register`,
`reporting/conclusions-and-controls`).

**Two tools.** `encrypted_survey` identifies candidate files using extension and
entropy heuristics, samples selected windows and tails of the first candidates,
and groups filesystem modification times by hour. These results guide the
examination; they do not establish how much was encrypted, whether a file is
recoverable, an encryption window or a family. Files it did not match, could not
measure or could not read have buckets of their own, and a census of every entry
is written whole. `ransom_note_scan` finds files whose names look like ransom
notes and locates what is in them (identifier-like strings, addresses, wallets) by
byte offset without printing them: it is a candidate inventory, a name match is not
a confirmed note, and its values go only to a sealed job file
(`write_values: true` in a job run with `secret_output: true`).

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
`encryptor/backup-infrastructure` skill: what to preserve, how to separate a guest's
compromise from the host's, and why a snapshot is not an independent backup. The
artefacts themselves (virtual-machine configuration, disk and snapshot chains, backup
job records) are read by the virtualization-backup-forensics pack when it is loaded;
the skill points to its tools without depending on it.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/ransomware-response
    scripts/swarm.sh start --pack computer-forensics-base,windows-forensics,ransomware-response ...
