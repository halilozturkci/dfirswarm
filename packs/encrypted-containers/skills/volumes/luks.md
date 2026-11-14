---
id: volumes/luks
title: LUKS volumes, headers and keyslots
when: A volume, image or detached header may be LUKS.
needs: []
card: Read in order: crypto_id ({"path": "<image>", "offset": <bytes>}) gives the signature and the version; crypto_metadata (the same arguments) runs cryptsetup luksDump on a copy of the header and returns keyslots, segments, digests and tokens as records. unavailable is not an empty slot list. A slot is one unlock path: not a count of passwords or people, not proof that it opens the data. LUKS2 keeps two metadata copies: compare them. With a detached header the data device carries no signature. Never repair, restore, convert or change slots on the evidence. Does not show: who added a slot or when, or that no usable key exists.
tools: [crypto_id, crypto_metadata]
requires_host: [cryptsetup]
---

Use only if the volume or a header file may be LUKS and you read its metadata. Not for an Apple volume (`volumes/filevault-apfs`) or for choosing the route (`volumes/luks-filevault`).

Read in this order. `crypto_id` gives the signature and the version. `crypto_metadata`
runs `cryptsetup luksDump` on a copy of the header and returns the keyslots, segments,
digests (never their salts) and tokens as records, or says `unavailable`: that is not
an empty slot list (a header copy `.cm-slice-*` under the output is removed unless the tool was killed with SIGKILL). `cryptsetup luksDump` reads the same metadata by hand. Use a
`cryptsetup` that supports the version you see. Do not use its options that disclose a
volume key in a metadata job.

LUKS1 has eight key slots. LUKS2 keeps keyslots, digests, segments and tokens as JSON
metadata in a primary and a secondary copy, and they only make sense read together: the
copies can differ, so compare them. A slot is one unlock path in the metadata: not a
count of passwords or people, not proof that it opens the data segment, and not evidence
of who added it or when (corroborate with configuration, backups and logs). A digest ties
keyslots to a segment; a token names where unlock material may be kept (its type), not
the material.

Record whether the header is embedded, detached, missing or damaged, and keep every
metadata copy and header backup with its provenance and what it belongs to. With a
detached header the data device carries no signature. Do not repair, restore, convert,
re-enrol or change slots on the evidence: a header backup can preserve an older unlock
path. A region with no signature and high entropy does not tell detached-header LUKS,
plain dm-crypt (no header at all), VeraCrypt, other ciphertext, compressed or random data
apart.

**Does not show.** Who added a slot or when; that a slot opens the data; that no usable
key exists; that the two metadata copies agree, unless they were compared.

**Sensitive output.** `cryptsetup luksDump`'s volume-key option prints key material:
leave it off for a metadata job. `crypto_id` prints no raw bytes of the file; it does
print header facts (the LUKS UUID, cipher names from a closed list, a LUKS2 label, slot
states, the sample's entropy), none of them key material. `crypto_metadata` prints no
salt, digest, UUID or label; it says whether each is present.
