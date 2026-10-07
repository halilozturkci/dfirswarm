# Encrypted Containers Pack

Working out what protects a piece of evidence, what its metadata shows without a
key, and where key material the case supplies may already be, before anybody
spends an hour on a way in.

Depends on the Computer Forensics Base Pack, whose `filesystem/encrypted` skill
covers the three reasons a volume will not open. This pack is what to do once you
know it is the encrypted one.

## What it carries

**Five skills**: `identify/headers`, `volumes/bitlocker`,
`volumes/luks-filevault`, `archives/protected`, `keys/where-they-hide`.

**Three tools.**
`crypto_id` names the scheme from the first bytes of a volume or file and reads
what a header holds without a key: the LUKS1 key-slot fields, the LUKS2 binary
header (version, label, UUID). It does not read LUKS2 keyslots, BitLocker
protectors or the encryption state of an APFS volume, and it names the reader
that does. `archive_probe` lists a ZIP's members with per-member encryption, and
says what it can and cannot establish about 7-Zip, RAR, PDF and OLE documents; a
result from a byte search is marked a heuristic, never "not encrypted".
`recovery_key_scan` sweeps a tree for text in the BitLocker 48-digit format,
private-key headers and the file names key files are saved under. It returns
where each is (file, offset, length, a structure check), never the value, a
fragment of it or a hash of it, and lists every file it could not read in full.

**One goal template**: `what-is-locked.md`.

## Secrets

A tool that can reach secret material answers with presence, kind, location,
length and offsets. A value is written only when the caller asks for it, only in
a job run with `secret_output: true`, and only to a file under `$OUT`.
`recovery_key_scan` is the reference implementation of this; `docs/packs.md`
("Secrets and sensitive output") has the pattern in full. No skill or report
writes a password, a PIN, a recovery value, a fragment of one, or a hash of one.

## Three things the skills insist on

**Read the metadata first.** A BitLocker volume's protector list, a LUKS header,
an archive's member table: what each shows is readable with no secret, and each
skill says what it does not show.

**Look in the evidence the case supplies.** Key material is sometimes already in
the case: a saved file, a backup, an escrow export, a memory capture. Locating it
is a bounded search with its coverage stated, and a hit is a lead until it opens
the object.

**Do not start a recovery you have not been asked for.** It may be outside the
authority the engagement gives you, and where the material is a third party's it
may be unlawful. Establish what the container is, report it, and ask.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/encrypted-containers
    scripts/swarm.sh start --pack computer-forensics-base,encrypted-containers ...
