---
id: volumes/luks-filevault
title: Choosing the LUKS or FileVault examination route
when: A Linux or Apple volume appears encrypted.
needs: [identify/headers]
tools: [crypto_id]
requires_host: [cryptsetup, fvdeinfo, fsapfsinfo]
---

LUKS and FileVault are different routes with different limits. Identify the format
before choosing a reader (`crypto_id` gives a lead, with its next reader), and keep
the original encrypted object and its metadata as they came.

**LUKS.** Use a `cryptsetup` that supports the version you see. `cryptsetup luksDump`
reads the header's metadata: version, UUID, data offset, cipher parameters and the
slots or keyslots. Do not use its options that disclose a volume key in a metadata
job.

LUKS1 has eight key slots. LUKS2 keeps keyslots, digests, segments and tokens as
JSON metadata, and they only make sense read together. A slot is one unlock path in
the metadata: not a count of passwords or people, not proof that it opens the data
segment, and not evidence of who added it or when (corroborate with configuration,
backups and logs).

Record whether the header is embedded, detached, missing or damaged, and keep every
metadata copy and header backup with its provenance and what it belongs to. Do not
repair, restore, convert, re-enrol or change slots on the evidence: a header backup
can preserve an older unlock path. A region with no signature and high entropy does
not tell detached-header LUKS, plain dm-crypt, VeraCrypt, other ciphertext,
compressed or random data apart.

**FileVault and APFS.** Say which layout you have. Use `fvdeinfo` (libfvde) for the
Core Storage layout that legacy FileVault 2 used; this pack does not establish that
the build in the image reads an APFS volume, so test it on the object, and where it
fails on one, call that a tool limit, not a finding about the volume. For an APFS container `fsapfsinfo` (libfsapfs) lists the volumes under the
limits its build documents (the macOS pack's `filesystem/apfs` states them, if that
pack is loaded). Which volume is encrypted, and how, is read by a reader validated
for that layout, or on an authorised macOS examination host: record the Mac model,
the processor and security hardware, the OS build and how the data was acquired.

Do not assume a user password or a recovery key makes a raw image readable away from
the original hardware. A personal recovery key, an institutional recovery mechanism,
an authorised management-system escrow record and account-assisted recovery are
different routes; which applies depends on hardware and configuration. The login
keychain and the volume are separate protected objects: opening the volume does not
show that every keychain item can be decrypted.

**Does not show.** Who added a slot or when; that a slot opens the data; that no usable
key exists; anything about an APFS volume's encryption from a reader that does not
support it.

**Sensitive output.** `cryptsetup luksDump`'s volume-key option and `crypto_id`'s
`include_head_hex` print key material: leave them off for a metadata job.

**Both routes.** Use material the case supplies, within the recorded authority. Jobs
that handle secret material run with `secret_output: true`; the ledger and the report
carry source locators, non-secret identifiers, sealed references and results, never
a value, a fragment or a hash. If contents stay inaccessible, state the format
observed, the metadata examined, the material available, the reader's limits, what
you asked for, and exactly which contents were not examined. Do not write that no
usable key exists.
