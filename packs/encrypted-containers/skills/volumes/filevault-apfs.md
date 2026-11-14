---
id: volumes/filevault-apfs
title: FileVault and APFS volumes
when: An Apple volume is encrypted: legacy Core Storage FileVault 2 or APFS.
needs: []
card: crypto_metadata ({"path": "<image>", "offset": <bytes>}) picks fvdeinfo or fsapfsinfo by the signature at the byte offset and shows the counts they print. An APFS container's software-crypto flag does not say that a volume is encrypted. Where a reader fails on the object, call that a tool limit, not a finding about the volume. Do not assume a user password or a recovery key makes a raw image readable away from the original hardware. Record the layout (Core Storage or APFS), the Mac model, the security hardware, the OS build, how the data was acquired and which reader was tested. Does not show: that opening the volume lets every keychain item be decrypted.
tools: [crypto_metadata]
requires_host: [fvdeinfo, fsapfsinfo]
---

Use only if the volume is an Apple one (Core Storage or APFS). Not for LUKS (`volumes/luks`).

**FileVault and APFS.** Say which layout you have. `crypto_metadata` picks `fvdeinfo` or
`fsapfsinfo` by the signature at a byte offset and shows the counts they print; for an
APFS container it also reads the container's software-crypto flag, which does not say
that a volume is encrypted. Use `fvdeinfo` (libfvde) for the
Core Storage layout that legacy FileVault 2 used; this pack does not establish that
the build in the image reads an APFS volume, so test it on the object, and where it
fails on one, call that a tool limit, not a finding about the volume. For an APFS container `fsapfsinfo` (libfsapfs) lists the volumes under the
limits its build documents (the macOS pack's `filesystem/apfs` states them, if that
pack is loaded). Which volume is encrypted, and how, is read by a reader validated
for that layout, or on an authorised macOS examination host: record the Mac model,
the processor and security hardware, the OS build and how the data was acquired. If the
macOS pack is loaded, its `filesystem/apfs` owns APFS structure and this note owns the
encryption-route decision: check the run's skills index.

Do not assume a user password or a recovery key makes a raw image readable away from
the original hardware. A personal recovery key, an institutional recovery mechanism,
an authorised management-system escrow record and account-assisted recovery are
different routes; which applies depends on hardware and configuration. The login
keychain and the volume are separate protected objects: opening the volume does not
show that every keychain item can be decrypted.

**Does not show.** Anything about an APFS volume's encryption from a reader that does not support it; that a user password or recovery key makes a raw image readable away from the original hardware; that opening the volume lets every keychain item be decrypted.

Record: the layout (Core Storage or APFS), the Mac model, the processor and security hardware, the OS build, how the data was acquired, and which reader was tested on the object.
Sensitive output: no tool here prints a key; jobs that handle secret material run with `secret_output: true` (`volumes/luks-filevault`).
