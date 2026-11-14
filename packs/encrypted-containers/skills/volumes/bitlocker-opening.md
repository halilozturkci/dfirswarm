---
id: volumes/bitlocker-opening
title: Opening a BitLocker volume with supplied material
when: The case supplies a recovery password, key file or escrow export to open the volume.
needs: []
card: With material the case supplies, in a job with secret_output: true, materialise_decrypted {"operation": "bitlocker_image", "source": "<image>", "offset": <bytes>, "key_kind": "recovery_password", "key_ref": "<sealed 0600 file>"} writes a raw image under $OUT. A recovery_key_scan hit is a transcription, not a working key. Does not show: that a failed route means the volume cannot be opened.
tools: [materialise_decrypted, recovery_key_scan]
requires_host: [bdemount, dislocker]
---

Use only if the case supplies a recovery password, a key file or an escrow export and you open the volume. Not for identifying the protectors (`volumes/bitlocker`).

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
the object instead of assuming. `materialise_decrypted` does this through pybde: a
sealed key reference in, a raw image and a provenance file out, the kind of key used
(not the protector's identifier) recorded, and a `.partial` file for what is not whole. `dislocker` and `bdemount` present a FUSE view; a
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

If opening fails, separate: material unavailable; a candidate that did not
validate; a reader that does not support this version; an incomplete acquisition;
damaged metadata. Say which contents were not examined. Do not call the volume
unrecoverable from one failed route: name the routes tried.

**Does not show.** That a hit that passes its structure check is a working key; that a mount is a sealed output; that a failed route shows the volume cannot be opened.

Record: the reader and its version, what was extracted and what failed, the hash of the derivative, which protector was used (by its non-secret identifier).
