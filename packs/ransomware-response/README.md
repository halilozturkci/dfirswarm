# Ransomware Response Pack

The order a ransomware case has to be worked in, and the two questions that
decide everything else.

Depends on the Computer Forensics Base Pack. It does not repeat the intrusion
work: the Windows, Linux, network and memory packs do that, and this one says
where in the sequence each belongs.

## What it carries

**Seven skills**: `scope/first-hour`, `exfil/before-encryption`,
`encryptor/traces`, `encryptor/destroyed-backups`, `identify/family`,
`recovery/what-is-possible`, `reporting/for-regulators`.

**Two tools.** `encrypted_survey` walks a tree and measures what was *actually*
encrypted — campaigns skip by extension, directory and size, and the skipped set
is routinely larger than anyone assumes. It reads every eligible file's head,
then the middle, end and tail of encrypted-looking samples, so a large database encrypted only at the front shows up as
recoverable rather than lost; it clusters modification times, which brackets
when the run happened; and it finds the bytes every encrypted file ends with,
which identifies the family better than the extension an affiliate can change.
`ransom_note_scan` finds the notes and pulls out the onion address, the victim
identifier a negotiator cannot proceed without, the contacts and the wallets.

**One goal template**: `ransomware-case.md`, whose checks will not pass without
an answer about exfiltration and a position on whether the operator still has
access.

## The order, and why it matters

Scope, then **exfiltration**, then entry and spread, then the encryptor. The
exfiltration question decides the regulatory clock and the negotiation, it is
answered from the evidence that ages fastest, and it is the one most often
started last.

And preserve before you restore. Every hour of restoration destroys evidence.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/ransomware-response
    scripts/swarm.sh start --pack computer-forensics-base,windows-forensics,ransomware-response ...
