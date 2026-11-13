---
id: recovery/scheme-from-sample
title: Key scheme from sample, dump and files
when: Encrypted files and the encryptor or its process dump are held; no public decryptor fits.
core: 3
needs: []
tools: [encrypted_survey, cipher_state_scan, stream_kpa_check, family_decrypt]
card: Encrypted family, no decryptor. (1) Measure what the encryptor added: encrypted_survey scheme_pointers (overhead against a plaintext twin, tails unique per file). A constant per-file trailer is where the per-file key usually is, plain or masked: test it first. (2) Read the routine to the key's last use: where is it written? (3) cipher_state_scan on the process dump, then stream_kpa_check with {"candidates": values_file} as key and nonce source: one key that opens one file is tried as the rule for all; partial says how far. (4) family_decrypt with the recipe file. No hit is a negative only after the planted control passed. Never quote a key.
---

Use when encrypted files of one family are held with the encryptor, its process dump or a plaintext twin, and no public decryptor fits. Not for obtaining a public decryptor (`recovery/public-decryptors`) or for how much of a file was encrypted (`encryptor/samples-and-notes`).

**Order of work**, on copies:

1. Measure what the encryptor added. `encrypted_survey` gives in `scheme_pointers` the smallest member, a member's overhead against a same-name plaintext twin, and whether the tails are unique per file. If the overhead is constant and the tail unique per file, that trailer is where per-file key material is usually kept, plain or masked by a constant: test it before hunting memory.
2. Read the encryption routine to the key's last use: where is the per-file key written, and what is it XORed or wrapped with? If the reverse-engineering pack is loaded, its notes read it.
3. If a process dump of the encryptor is held, `cipher_state_scan` lists cipher states and key schedules in it by offset. A hit is a candidate until a file opens with it.
4. `stream_kpa_check` takes the members and key and nonce sources (the scan's values file, a constant, a slice of each member) and says per member which combination gives the expected first bytes. One known (file, key) pair verifies any footer hypothesis: when a dump key opens one member, it tries that key XOR the member's own tail on every other member and writes the recipe. A `no_match` beside a rule that opens others may be a file not of its name's type.
5. `family_decrypt` applies the recipe file to every member, with a receipt each.

**Record.** The jobs, the offsets of the hits, the check's `outcome` and `tried`, the receipts file, and the rule in words, never a key.

**Does not show.** A scan with no hit is a negative only after its planted control passed, and only for the shapes it lists. `no_combination_matched` names what was tried; it does not mean that no key exists. A match is the expected first bytes on a crib of the stated length: a 4-byte crib needs the rule to hold on other members. Decryption authenticates nothing: `type confirmed` is first bytes only, so open a file with its own reader before relying on it.

Sensitive output: cipher_state_scan, stream_kpa_check and family_decrypt run as secret-output jobs (their manifests require it). Keys, nonces, masks and decrypted content stay in the job's files; the ledger cites job, file and offset, never a value or its hash.
