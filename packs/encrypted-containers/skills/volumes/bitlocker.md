---
id: volumes/bitlocker
title: BitLocker protectors and authorised examination
when: A Windows volume may use BitLocker.
needs: []
tools: [crypto_id]
requires_host: [bdeinfo]
---

Use when a Windows volume may use BitLocker and you identify its protectors. Not for opening it with supplied material.

Establish the volume boundary first and keep the encrypted object as it came.
Record the device and volume identifiers, the offset and sector size, the
acquisition type, the reader's name and version, and the Windows build where
something independent gives it.

BitLocker encrypts the volume with a full-volume encryption key (FVEK). A volume
master key (VMK) protects the FVEK, and each protector is a route to the VMK.
`crypto_id` recognises the FVE signature (offset 3 of the volume) and nothing more;
it does not read protectors. `bdeinfo` records the protectors and metadata it can
interpret in the build you have. Its list is what that build parsed for this
metadata version, not proof that no other protector exists: say which version read
it.

Tell the kinds apart: recovery password, external or startup key, password,
TPM-based protectors, and a clear key where one is observed. A directory service
or a cloud identity is a possible escrow location for a recovery password, not a
protector type of its own on the disk.

A TPM-only protector cannot ordinarily be satisfied from a standalone image: the
image lacks the chip and the platform state it was sealed to. Record separately
what the case supplies instead: another protector's material, an authorised
acquisition from a running machine, or escrowed recovery material. Do not change
the original device's boot or protection state.

A clear key may be present while protection is suspended. Its presence shows the
volume can be read without a secret at that point. It does not show why
protection was suspended, who suspended it, or that anyone forgot to resume it:
corroborate state and timing in the device's own logs and records.

For removable media read the actual metadata. A legacy discovery volume (a plain
FAT header) may be present, and neither its presence nor its absence decides
whether BitLocker To Go protects the contents.

Only if the case supplies a recovery password, key file or escrow export and you open the volume: `volumes/bitlocker-opening`.

**Does not show.** That a located or escrowed value opens this volume; why protection
was suspended, or by whom; that a protector list is complete; that a TPM-only volume
can be opened from an image; what the contents are before a validated opening.

**Sensitive output.** `crypto_id` prints no raw bytes of the file. Record which protector was used and a reference to the sealed source of any secret, never the secret (`volumes/bitlocker-opening`).
