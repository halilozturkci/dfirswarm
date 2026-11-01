---
id: files/aescrypt
title: AES Crypt files
when: A file starts with the AES Crypt signature, or carries the .aes extension.
needs: []
tools: [materialise_decrypted]
requires_host: []
---

Use only if a file is an AES Crypt container and you open it with a password the case supplies. Not for archives with their own password (`archives/protected`).

An AES Crypt file starts with the bytes `AES`, then a version byte (0, 1 or 2). Version 2
adds extension records (a creator tag, for one) before the key material, and ends with the
encrypted data, a byte for the length of the last block, and an HMAC over it. Record the
version, the file's size and who supplied the password and on what authority.

Open it with `pyAesCrypt`, through `materialise_decrypted` (operation `aescrypt_decrypt`):
the password is read from a sealed 0600 file, the job runs with `secret_output: true`, the
output is a file under `$OUT` with a provenance file, and the HMAC is checked by the module
before the file is named a result. A library tool for AES Crypt version 2 may be in the
run's tool inventory (the tool library, loaded on request): use it only when the case asks
for it by name.

Tell the failures apart as far as the format lets you. A version 2 container whose length is not that
of a whole file is a cut copy, and nothing is decrypted. A wrong password and a damaged file
both fail the HMAC and look alike: say that the attempt failed, not which of the two it was.
Plaintext that was written before the HMAC passed is never a result; it stays an unverified
`.partial`.

**Does not show.** That a failed attempt means the password is wrong or the file damaged;
what the plaintext is before the HMAC passed; who encrypted the file or when.

**Sensitive output.** The password is never on a command line or in a report: cite the
sealed reference. Never write a password, a fragment of one or a hash of one.
