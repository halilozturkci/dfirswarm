---
id: volumes/veracrypt-truecrypt
title: VeraCrypt and TrueCrypt containers
when: A file or partition may be a VeraCrypt or TrueCrypt volume, which has no signature.
needs: []
tools: [crypto_id, tcrypt_header]
requires_host: [cryptsetup, mmls]
---

Use only if a file or partition with no signature may be a VeraCrypt or TrueCrypt volume. Not for naming the format from a signature (`identify/by-format`) or for LUKS (`volumes/luks`).

These volumes leave no signature, so nothing here is an identification. High entropy over
the whole object (`crypto_id`) and a size that is a whole number of sectors are leads,
next to other ciphertext, compressed or random data, wiped space, a detached-header LUKS
volume, plain dm-crypt, and a wrong offset or storage layer. Say which you ruled out and
how.

Ask what hosts it. A container file can sit anywhere in a file system; a partition or a
whole device that is encrypted starts at the volume's own offset, so find the offset
first (`mmls`, the partition table) and give it in bytes. A hidden volume lives inside
the free space of an outer one and has a header of its own at another place, and a normal
header that fails says nothing about a hidden one. A backup header sits at the end of the
volume: try the normal, the hidden and the backup region as separate attempts.

When the case supplies a candidate password, and a keyfile if there is one, `tcrypt_header`
reads the header with it over cryptsetup's tcrypt mode: the password comes from a sealed
0600 file, the job runs with `secret_output: true`, and the answer is whether a header
decrypted and its non-secret fields (cipher chain, mode, PBKDF, key size, sizes). A PIM
is not supported by this version: the call is refused and says so.

**Does not show.** That a header that did not decrypt means the object is not VeraCrypt or
TrueCrypt; that high entropy identifies it; that an attempt covered the hidden and backup
regions unless each was tried.

**Sensitive output.** `tcrypt_header` never prints the volume key, a salt or the password.
Record the region tried and a reference to the sealed source of the password, never the
password.
