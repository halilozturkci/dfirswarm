---
id: volumes/luks-filevault
title: LUKS and FileVault
when: A Linux or macOS volume is encrypted.
needs: [identify/headers]
tools: [crypto_id]
requires_host: [cryptsetup, fvdeinfo]
---

**LUKS** puts its metadata in the clear at the front of the partition, and that
metadata answers several questions without any key.

    cryptsetup luksDump part.img
        version, cipher, key size, the UUID
        one entry per key slot, ENABLED or DISABLED

**The slot count is a finding.** LUKS1 has eight slots; each enabled slot is a
separate passphrase or key file that can open the volume. LUKS2 describes its
keyslots and tokens in JSON metadata and is not limited to the LUKS1 layout.
Extra slots establish extra unlock paths, but the header does not by itself
establish who added them or when; correlate configuration, backups and logs
before making that attribution.

A LUKS header can be **detached** — kept on separate media, with the partition
holding only ciphertext. A partition that is high-entropy from byte zero with no
magic at all is either that or VeraCrypt, and the exhibit list usually settles
which.

**FileVault** on a modern Mac is APFS volume encryption, and `fvdeinfo` reads
the metadata: the encryption method and the key material references. What it
does not give you is the key, which is wrapped by the user's password, by a
recovery key, or escrowed to an institutional key or to iCloud.

Three places a FileVault case is actually solved:

- the **recovery key**, printed or escrowed at enrolment by whoever manages the
  fleet;
- an **institutional key** (`FileVaultMaster.keychain`), which a managed estate
  holds centrally;
- the user's own password, obtained lawfully.

**The keychain is not the volume.** `login.keychain-db` is encrypted with the
user's password and holds a great deal else; unlocking the volume and unlocking
the keychain are two separate problems with two separate answers, and a report
should not conflate them.

For either scheme, when you cannot open it, say so as a finding: "the second
volume is LUKS2 with two enabled key slots and no key was available, so its
contents were not examined" is complete and defensible.
