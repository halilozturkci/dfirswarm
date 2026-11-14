---
id: data/glyphs
title: Exact characters
when: Text read off a picture must be exact.
card: glyph_strip: {"image": "<crop of ONE line>", "reading": "<as you read it>", "uncertain": [{"at": 4, "among": "lI"}, {"at": 9, "among": "'`"}]} (positions from 0, spaces counted). A reading with a confusable character (' `, l I 1, O 0) is recorded at MEDIUM confidence as a candidate set (candidate_set_size, candidates_file), never as one string. count is ink runs: touching characters count once (wide), a two-stroke character twice (narrow_pairs); look at strip.png. The reading, OCR text and candidates are files, never in the answer; for a credential run it with secret_output: true.
needs: []
tools: [glyph_strip]
requires_host: [tesseract]
---

Use when a conclusion rests on the exact characters of a line in a screenshot, a photograph or a video frame: a password, a key, an address, an identifier. Not for the gist of a page (`data/documents-media`) or a QR symbol (`data/qr`).

    job_run tool=glyph_strip args={"image": "work/<you>/line.png", "reading": "<as you read it>", "uncertain": [{"at": 4, "among": "lI"}]}

1. **Crop one line first** (Pillow, in your own script), with a margin, at native size: take a video frame at native size, not a tile.
2. **Count before you read.** `count` is the number of ink runs. If your reading has another number of characters besides spaces, one of you is wrong: look at `strip.png`, where every glyph carries its index, and at `wide` (maybe two touching characters) and `narrow_pairs` (maybe one character in two strokes).
3. **A confusable character makes a candidate set.** An apostrophe or a backtick, l or I or 1, O or 0: name each such position in `uncertain` with the characters it could be. The reading is then recorded at **medium** confidence as a candidate set of `candidate_set_size` with `candidates_file`, never as one string. Glyphs that are the same drawing and read as one character are tied and counted once; `same_drawing_read_apart` names a pair read as two: look again.
4. **A second reader is not a proof.** Where `tesseract` is installed the tool runs it and `readers` says who read what; where it is not, `ocr` says so. Two readers that agree share the picture's defects (`picture_damaged`: a cut crop, ink may be missing); where they differ (the file `reading_against_ocr` names), make that position uncertain.
5. **Resolve a set by use, not by looking harder:** the candidate that opens the archive or matches a stored verifier, on the basis the case allows (`evidence/scope`), is the reading. Until then report the set.

**Record.** The crop and its source (picture, region or frame), the count, the reading's confidence, the set's size and file, each reader and its version.

**Shows.** How many separate marks the line has and which readings are open. **Does not show.** Which candidate is right, or who wrote the text.

**Sensitive output.** The reading, the OCR text and the candidates can be a credential: they are files, never in the answer, and an argument is recorded in the trace. For a credential run the job with `secret_output: true` and cite the file.
