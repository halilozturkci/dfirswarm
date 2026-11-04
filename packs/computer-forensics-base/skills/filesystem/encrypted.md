---
id: filesystem/encrypted
title: Tell encryption from other causes of unreadability
when: A reader cannot open a source, or validated metadata identifies encryption.
needs: []
tools: []
requires_host: [fsstat, fls, bdeinfo]
mentions: [crypto_id]
---

Use when a reader cannot open a source, or a signature suggests encryption. Not for reading a protector list or opening a volume (`filesystem/encrypted-metadata`).

An unreadable volume (`fsstat` refuses it, or the listing is one file you cannot open) is an observation, not a diagnosis. Keep these apart and test them as separate hypotheses, recording the exact failure of each: a wrong offset or sector size, missing or truncated segments, a mapping layer (LVM, RAID, Storage Spaces), a format or feature the installed reader does not handle, damage or overwriting, and encryption. Rule the cheap ones out first with `evidence/imaging` and `filesystem/layers`. Unreadability alone establishes none of them. A volume `fls` lists is readable at the volume level; encryption of single files is below.

**Identify encryption from metadata, not from absence.** A signature is a lead to the parser that reads that scheme's header:

    BitLocker   "-FVE-FS-" near the start of the volume (offset 3 on a volume encrypted in place); bdeinfo confirms it
    LUKS        "LUKS\xba\xbe" at offset 0 of the device or of a detached header file
    FileVault   a CoreStorage or APFS container with an encrypted volume (two different mechanisms)

A volume with no recognised header and random-looking content is an unidentified high-entropy region. VeraCrypt or TrueCrypt is one explanation; a wiped or compressed region, an overwritten header, a format no reader here knows and a wrong offset are others. Report its offset, size and what was ruled out, and name no product. If the encrypted-containers pack is loaded (check the run's tool inventory), its `crypto_id` and `identify/headers` read headers further.

**Encrypted at the file.** The volume reads and individual files do not: office documents, archives, containers. That is an ordinary extract and a different question. Identify the format and the kind of protection from its structure before choosing a reader; where a key might be is a question for the case sources the examination may search (`evidence/scope`).

**Not encrypted, just unreadable.** A volume manager, a damaged partition table, a sparse or truncated image, or an offset that is wrong: all more common than encryption and cheaper to fix. See `evidence/imaging`.

**Write it as a bounded finding, not an obstacle:** "the second volume's metadata identifies BitLocker with a recovery-password protector and no clear key; no key material was supplied or found in the sources searched (named), so its contents were not read with this reader". That is a limit of this examination, not a statement that no route exists.

**Does not show.** A BitLocker or LUKS header shows the format is present, not that the data is intact, was in use, or is recoverable.

**Sensitive output.** `bdeinfo` prints salts, digests and protector identifiers: run it as a job and keep them out of posts (`filesystem/encrypted-metadata`).
