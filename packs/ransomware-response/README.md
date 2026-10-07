# Ransomware Response Pack

Evidence-led ransomware examination. Its two tools return candidates; what a
candidate shows has to be validated before anyone acts on it.

Depends on the Computer Forensics Base Pack. It does not repeat the intrusion
work: the Windows, Linux, network and memory packs do that, and this one says
where in the work each belongs. Where a skill names a tool of another pack, it
says "if that pack is loaded" and asks you to check the run's tool inventory.

## What it carries

**Seven skills**: `scope/first-hour`, `exfil/before-encryption`,
`encryptor/traces`, `encryptor/destroyed-backups`, `identify/family`,
`recovery/what-is-possible`, `reporting/for-regulators`.

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
no examination method for hypervisors or network storage yet. `yara` is declared for
rules the case supplies.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/ransomware-response
    scripts/swarm.sh start --pack computer-forensics-base,windows-forensics,ransomware-response ...
