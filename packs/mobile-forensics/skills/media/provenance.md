---
id: media/provenance
title: Media originals, derivatives and capture time
when: A photo or video is cited, and you must say whether you hold the original and when it was made.
needs: []
tools: [heic_inspect, sqlite_query]
requires_host: [exiftool, heif-convert]
---

Use when you cite a photo, video or attachment. Not for where the device was (`location/sources`) or for the message that carried it (`apps/messaging`).

**Original or not.** A thumbnail, a placeholder, a cloud-optimised copy, an edited render and a shared-library item are not the original. Cite the path, the size and the digest of what you hold, and say which kind it is. The photo library's database names the edit and the original resource; read its table definitions with `sqlite_query` on a copy before you rely on a column.

**Capture, import and sync times differ.** The time inside the file (`exiftool` on the original), the library's date added, the file time on disk and a message's send time are four clocks. Keep the raw values and name the clock; a capture time is a claim by the device, and its zone may be absent.

**HEIC.** `heic_inspect` makes a preview of a HEIC or HEIF original and ties it back: both identities, the dimensions, the image count, the primary item. It walks the container's boxes without a decoder, and it reads the metadata from the original with `exiftool`, never from the preview. One backend per run is recorded: `heif-convert` or `pillow-heif`. The preview is a derivative: cite the original; a size or pixel limit refuses a conversion before it starts, and the answer says so. The answer carries presence and counts of metadata, not values; the values go to a file only in a job with `secret_output: true`.

**Conversion stays apart.** Keep the converted file next to the original's digest and the backend and its settings; never overwrite the original or let the preview's metadata stand in for it.

Shows: whether you hold an original or a derivative, the container's structure, and the clocks the file carries.

Does not show: who took the picture, that the capture time is true, or that a picture was not edited.

Record: path, size, digest, kind, each clock with its source, the backend and its settings.

Sensitive output: GPS positions, device serials and names in metadata are personal data; run `heic_inspect` with `write_values` only as a job with `secret_output: true`, and cite that a tag exists and where.
