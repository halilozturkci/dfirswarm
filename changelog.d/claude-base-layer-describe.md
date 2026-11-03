### Added: computer-forensics-base

`layer_describe` turns declared image sources and a sector size into one immutable JSON descriptor. The sources are an
E01/S01/Ex01 set's segments, the segments of a split raw image, or a virtual disk (VMDK, VHD, VHDX, QCOW) and the files it
depends on; 512 and 4096 byte sectors both work. Nothing outside the declared list is looked for, listed or opened, and
nothing is mounted. Each source is opened without waiting and without following a link, sized, and hashed with sha256 (or
`not_hashed`, with the reason); the container is named from its bytes. An EWF set is checked against its naming run and the
chain of section descriptors of each segment; a QCOW2 backing file, a VMDK parent or extent and a VHD parent are read from
the headers and must be among the declared sources, otherwise they are `missing_dependencies` and `mmls`, `fsstat`,
`img_stat`, `ewfinfo` and `qemu-img` are not run on that disk (they would look for the file by name outside what was
declared). `qemu-img info` is run without `--backing-chain`. The partition table is true, false or unknown, and each
allocated slot is read with `fsstat` at its offset. The descriptor is canonical JSON with no clock in it, written as
`layer-<sha256 of its bytes>.json` (mode 0600, never replaced): the same inputs give the same bytes and the same name. It
holds the declared paths as given, because a consumer must open them; the answer prints them through the shared withholding.
`complete` only when every source was read and hashed, nothing declared is missing and every allocated slot was read. A
VHDX parent locator and an AFF image are not examined, an EWF2 set is never `complete`, and Dissect's `target-query` is
not used. `filesystem/layers` names it. The `qemu-img` JSON keys it reads (`format`, `virtual-size`, `backing-filename`) are the ones qemu documents, and `qemu-img` was not installed where it was tested; the VMDK, VHD and QCOW header readers were tested on headers built from the formats' layouts, not on files a hypervisor wrote.
