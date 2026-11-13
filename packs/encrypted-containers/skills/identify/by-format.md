---
id: identify/by-format
title: Encryption signs by format, and their limits
when: You name BitLocker, LUKS, Apple, VeraCrypt, archive, Office or PDF protection from a signature.
needs: []
card: crypto_selftest ({}) runs each installed reader on a synthetic sample and says parsed, not parsed or unavailable: that is about the sample, not about your volume. crypto_id ({"path": "<image>", "offset": <bytes>}) gives a lead, not a format's protection: an FVE signature is a lead for a metadata reader; an APFS container signature does not show every volume is encrypted; high entropy, an aligned size and no signature do not identify VeraCrypt or TrueCrypt. Once the case supplies a candidate password, tcrypt_header ({"source": "<volume>", "password_file": "<sealed 0600 file>"}) reads a header, only in a secret_output job. Does not show: that a supported archive container is encrypted.
tools: [crypto_id, crypto_selftest, tcrypt_header]
requires_host: [cryptsetup]
---

Use only if you name a particular format's protection from what the first pass showed. Not for the first pass (`identify/headers`).

- BitLocker: an FVE signature is a lead for a metadata reader (`volumes/bitlocker`).
  An `MSWIN4.1` OEM string alone does not make a volume BitLocker To Go.
- LUKS: validate the magic and the version. Read LUKS1 key-slot metadata, or LUKS2
  metadata copies with their keyslots, digests, segments and tokens. An active slot
  is not a count of passwords, people or usable keys (`volumes/luks-filevault`).
- Apple: tell legacy Core Storage (FileVault 2) from APFS. An APFS container
  signature does not show that every volume is encrypted.
- VeraCrypt and TrueCrypt: high entropy, an aligned size and no signature do not
  identify them. Keep other ciphertext, compressed or random data, wiped space,
  damaged metadata and a wrong offset or storage layer as the alternatives. Once
  the case supplies a candidate password, `tcrypt_header` reads a header with it
  over cryptsetup's tcrypt mode.
- Archives: identify the container, each member's protection and the header's
  protection as separate facts (`archives/protected`). A supported container is not
  necessarily encrypted.
- Office: read the compound-file streams and the encryption structure; do not apply
  PDF owner and user password terms to Office. PDF: encryption, the opening
  password and permission restrictions are different things, and a file that opens
  with an empty password may still be encrypted.
- Encrypted phone backups belong to the mobile pack, when it is loaded.
- A reader that fails on your object may be absent or broken. `crypto_selftest` runs
  each installed reader on a synthetic sample and says parsed, not parsed or
  unavailable; that is about the sample, not about your volume.

**Does not show.** That an APFS signature means every volume is encrypted; that high entropy and no signature identify VeraCrypt or TrueCrypt; that a supported archive container is encrypted; that an `MSWIN4.1` OEM string alone makes a volume BitLocker To Go.

Sensitive output: `crypto_id` prints no raw bytes of the file, so a possible key file is never shown (`identify/headers`). `tcrypt_header` takes the password from a sealed file and runs only in a `secret_output` job; it never prints the volume key, a salt or the password.
