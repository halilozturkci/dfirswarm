---
id: data/documents-media
title: Document and image content is its own layer
when: A PDF, an Office file, an image or a media file is the evidence, or holds it.
core: 2
needs: []
tools: []
requires_host: [pdftotext, exiftool, steghide]
---

Use when a document or an image carries the answer. Not for a protected or macro-bearing document's structure (check the run's tool inventory for a document-structure reader), for archives (`evidence/archives`) or for a phone's media database (the mobile pack, when loaded).

Five layers, five claims:
1. **The file's bytes.** Hash it; every other layer is derived from it (`evidence/provenance`).
2. **What it shows when rendered.** Cite the page or region.
3. **Extracted text.** `pdftotext` gives the text layer, not the page: reading order can differ (`-layout` keeps columns), text can be hidden or sit under an image, and a scanned page has none. Say which text you used.
4. **Embedded objects and earlier revisions.** Images, attachments, scripts and fonts inside a file, and the earlier revisions a PDF keeps when it is updated by appending. List them; never open one as code, and treat a recovered revision as a candidate until its structure parses.
5. **Metadata.** `exiftool` prints EXIF, XMP and PDF or Office properties without changing the file. These are values the creating software or a user wrote and can edit: author, application, device, GPS and times are claims of the file. A time there carries no zone unless the field says so (`timeline/clocks`). Absent metadata is not an absent event: editors and services strip it.

**Images.** Use Pillow in your own read-only script to look at pixels, bit planes and a re-saved copy for comparison; in a job write the copy under `{OUT}` (in your shell, `work/<you>/`), never over the original. A re-save rewrites metadata and recompresses, so do not hash or date it as the original. Record the library version.

**OCR.** Text read from an image is a reading with an error rate. Keep the image region beside the text, and check the characters a conclusion rests on (an identifier, an amount, a name) by looking at them.

**Concealment.** Look for hidden content when the question or the case scope names it (`evidence/scope`), not as a habit. Oddities (trailing bytes after a format's end marker, a size the content does not explain) are leads, not proof. `steghide` extracts from JPEG, BMP, WAV and AU files given a passphrase the evidence supplies (an empty one included); it cannot tell a file with nothing hidden from one hidden under another passphrase, so a negative is about that passphrase and about steghide only. Check `steghide --help` for how it takes the passphrase; the argument list is recorded in the trace, so if it takes it only as an argument, say so in the report. Guessing passphrases is not an examination step.

**Record.** The file's digest, the tool and version, the page or region, which layer a statement is about, and the metadata field it came from.

**Shows.** What the file contains and says about itself. **Does not show.** Who made or opened it, when the content was true, or that the metadata is genuine.

**Sensitive output.** Text, metadata and extracted hidden data can hold names, locations, credentials and card numbers. Run the extraction as a job with `secret_output: true` when it may, and cite the file and the page or offset, not the text.
