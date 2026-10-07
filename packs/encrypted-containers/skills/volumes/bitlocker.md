---
id: volumes/bitlocker
title: BitLocker protectors and authorised examination
when: A Windows volume may use BitLocker.
needs: [identify/headers]
tools: [crypto_id, recovery_key_scan]
requires_host: [bdeinfo, bdemount, dislocker]
---

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

For a recovery password or a key file keep its supplied provenance, and match the
non-secret identifiers it carries against the volume's protector identifiers. An
escrow export names its source system, device, retrieval time and rotation history;
an old record may belong to a protector that is not the one in this image.
`recovery_key_scan` locates candidates in the evidence (see `keys/where-they-hide`);
a hit that passes its structure check is a transcription, not a working key.

Open only with material the case supplies, within the recorded authority, as a job
with `secret_output: true`. Take the secret from a sealed file, in process, through
a user-space reader: `libbde-python` (pybde) and `dfvfs` are declared for this, and
the build in the image decides which volumes and protectors they handle, so test on
the object instead of assuming. `dislocker` and `bdemount` present a FUSE view; a
mount lives in that VM only and is not a sealed output, and mounting may be
unavailable in a worker. Whatever reader you use, write the decrypted volume, or
the scoped files taken from it, under `$OUT` as files, with the reader and
version, what was extracted, what failed, and a hash of that derivative. A reader
that can take the secret only on its command line puts it in the recorded trace:
say so in the report, so the trace can be redacted before it is shared.

**Sensitive output.** `recovery_key_scan` reaches secret material: run it as a job
with `secret_output: true`, and cite what it finds by file and offset. Never write a
recovery password, a fragment of one, or a hash of one; record which protector was
used, a reference to the sealed source of the secret, and the result.

For removable media read the actual metadata. A legacy discovery volume (a plain
FAT header) may be present, and neither its presence nor its absence decides
whether BitLocker To Go protects the contents.

**Does not show.** That a located or escrowed value opens this volume; why protection
was suspended, or by whom; that a protector list is complete; that a TPM-only volume
can be opened from an image; what the contents are before a validated opening.

If opening fails, separate: material unavailable; a candidate that did not
validate; a reader that does not support this version; an incomplete acquisition;
damaged metadata. Say which contents were not examined. Do not call the volume
unrecoverable from one failed route: name the routes tried.
