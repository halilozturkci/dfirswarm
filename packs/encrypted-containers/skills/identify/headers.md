---
id: identify/headers
title: Identifying encrypted evidence and its limits
when: A volume, archive or document may be encrypted.
needs: [filesystem/encrypted]
tools: [crypto_id, file_type]
requires_host: []
---

Identify the storage layer before interpreting encryption. Record the source
object, the acquisition type, the logical-stream path, the partition offset and the
sector size. `crypto_id` takes a byte offset into the file you give it: an offset
in a logical disk is not an offset in its E01 or virtual-disk wrapper (see
`evidence/imaging`).

Use `file_type` and `crypto_id` to triage, then check the proposed format with a
reader that supports the version you see. Record the reader and its version, the
fields it read, and any damaged, missing or unsupported structure.

`crypto_id` shows a recognised signature at the offset, the header fields at fixed
places (LUKS1 slot table; LUKS2 version, label, UUID), the basis of the call, the next
reader, and what is not determined.

**Does not show.** BitLocker protectors, LUKS2 keyslots, whether an APFS volume is
encrypted, document encryption, or whether any data is intact or openable. "No scheme
recognised" is not "not encrypted".

- BitLocker: an FVE signature is a lead for a metadata reader (`volumes/bitlocker`).
  An `MSWIN4.1` OEM string alone does not make a volume BitLocker To Go.
- LUKS: validate the magic and the version. Read LUKS1 key-slot metadata, or LUKS2
  metadata copies with their keyslots, digests, segments and tokens. An active slot
  is not a count of passwords, people or usable keys (`volumes/luks-filevault`).
- Apple: tell legacy Core Storage (FileVault 2) from APFS. An APFS container
  signature does not show that every volume is encrypted.
- VeraCrypt and TrueCrypt: high entropy, an aligned size and no signature do not
  identify them. Keep other ciphertext, compressed or random data, wiped space,
  damaged metadata and a wrong offset or storage layer as the alternatives. This
  pack provides no reader for them.
- Archives: identify the container, each member's protection and the header's
  protection as separate facts (`archives/protected`). A supported container is not
  necessarily encrypted.
- Office: read the compound-file streams and the encryption structure; do not apply
  PDF owner and user password terms to Office. PDF: encryption, the opening
  password and permission restrictions are different things, and a file that opens
  with an empty password may still be encrypted.
- Encrypted phone backups belong to the mobile pack, when it is loaded.

**Sensitive output.** `crypto_id` prints no raw bytes unless `include_head_hex` is
true: leave it false when the input may itself be a key or credential file, and do
not copy those bytes into the report or the ledger. Run any job that may emit secret
material with `secret_output: true`, and record locations and sealed references,
never values or hashes.

Before opening anything, fix the question and the authority for examining it. Use
keys and passwords the case supplies, or that were found within that authority; a
clear-key path that needs no secret is still not authority. If the material is not
supplied, see `keys/where-they-hide` for how to look in the evidence, and ask before
trying anything further.

An unreadable volume is not necessarily encrypted. Rule out a volume manager, a
damaged partition table, a sparse or truncated image and a wrong offset first
(`evidence/imaging`): they are cheaper to fix and common.

Report exactly one of: format and protection state confirmed (by which reader);
format suspected (on which observations); unsupported or damaged; not determinable.
A failed mount and a missing signature are not findings that encryption is absent.
