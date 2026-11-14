---
id: volumes/layered-reading
title: Reading an encrypted volume through its layers
when: An encrypted volume sits inside a disk image or virtual disk and you open it in user space.
needs: [filesystem/layers]
card: An offset means something only inside one layer: say which layer each number belongs to (wrapper, virtual disk, partition table, encryption layer, file system). Name the encryption layer at its own byte offset: crypto_id, then crypto_metadata ({"path": "<image>", "offset": <bytes>}). Write the unlocked layer out with materialise_decrypted ({"operation": "luks_image", "source": "<image>", "offset": <bytes>, "key_ref": "<sealed 0600 file>"}; bitlocker_image for BitLocker) in a job with secret_output: true; a mount is not a sealed output. Validate the result: size, first sector, then a read-only file system reader. Does not show: that a layer nobody opened holds nothing.
tools: [crypto_id, crypto_metadata, materialise_decrypted]
requires_host: []
---

Use when an encrypted volume is wrapped in other layers and you read it without a mount. Not for walking the layers of an image that holds nothing encrypted (`filesystem/layers`).

An offset means something only inside one layer. Go in order and say which layer each
number belongs to: evidence wrapper (E01, split raw), virtual disk (VHD, VHDX, VMDK,
QCOW2), partition table, encryption layer, file system. Keep the offset of each layer in
its own units, the sector size, the reader and its version.

User-space readers work as files, with no root and no mount (a mount made in a VM is that
VM's alone and is not a sealed output): `libvhdi-python` (pyvhdi) for a VHD,
`libluksde-python` (pyluksde) for LUKS, `libbde-python` (pybde) for BitLocker, `pytsk3`
for a file system read from a byte stream, `dfvfs` for several layers stacked in one
process, `pyAesCrypt` for an AES Crypt file. The build in the image decides which formats
and versions they handle: test them on the object, and call a reader's refusal a tool
limit until another reader agrees.

Name the encryption layer at its own offset (`crypto_id`, then `crypto_metadata`), then
write the unlocked layer out as a file: `materialise_decrypted` gives a raw image of the
unlocked volume under `$OUT` with a provenance file, from a key in a sealed file, and
keeps what is not whole as an unverified `.partial`. Validate the result before reading
it as evidence: its size against the unlocked size, the first sector against a file
system signature, then a read-only file system reader on the image.

**Does not show.** That a layer that opened is the one the system used; that a layer
nobody opened holds nothing; that a reader that refuses a volume shows it is damaged.

**Sensitive output.** Never write a key, a fragment of one or a hash of one. The unlocking
job runs with `secret_output: true`; the report cites the sealed reference and the result.
