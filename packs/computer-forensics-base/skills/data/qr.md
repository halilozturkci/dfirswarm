---
id: data/qr
title: QR symbols
when: A QR code in a picture, damaged or in pieces.
card: qr_read: {"image": "<picture>"} reads a whole symbol and, by itself, one with a finder erased or overdrawn (or {"mode": "repaint"}). Pieces of ONE symbol go together: {"mode": "fragments", "images": [..]}, never a call a piece. The payload is a file (payload_file), never in the answer: cite the picture, the file, version, level, mask and errors_corrected. "not a symbol" covers these methods only (looked_for, not_read): perspective, versions 11+, other symbologies are not read. An otpauth or Wi-Fi payload is a credential: run it with secret_output: true.
needs: []
tools: [qr_read]
requires_host: []
---

Use when a picture, a screenshot or a video frame shows a QR symbol whose content matters. Not for other symbologies (Data Matrix, Aztec, bar codes: `qr_read` does not read them) or text in a picture (`data/glyphs`).

    job_run tool=qr_read args={"image": "work/<you>/shot.png"}
    job_run tool=qr_read args={"mode": "fragments", "images": ["work/<you>/p1.png", "work/<you>/p2.png"]}

1. **Whole symbol:** the default call. Read `rows`: `decoded` with version, level, mask and `errors_corrected`, or `not a symbol`. Every frame of an animated picture or page of a TIFF is searched (`frame` says which decoded), and every symbol of a frame up to 8: the others are in `other_symbols_decoded`, each with its own payload file. `frames_not_read`, `picture_damaged` (a PNG cut or corrupt, a JPEG cut and given its end marker back: Pillow fills the rest with grey), `jpeg_data_not_walked`, `finder_patterns_not_read` or `symbols_past_the_bound` makes the answer partial (`not_read_or_judged` counts each): say what was not read.
2. **A finder erased or overdrawn:** the default call tries the repaint reading too; `mode: repaint` forces it and writes a repainted copy. The grid then comes from the two finders left or from the box of the dark pixels (`box` when other content is in the picture), and `located_by` says which.
3. **Pieces:** give every piece in one call with `mode: fragments`. `placements` says where each went, and `modules_not_covered` how much was missing. Pieces must be rectangular, upright to each other and of one scale. A piece in `pieces_contradicting_the_symbol` is damaged or from another symbol: the payload is not shown to be the whole set's; say so.
4. **A negative is bounded.** `not a symbol` holds for the methods in `looked_for`, after the planted control was read; `not_read` lists what they do not reach (perspective, versions 11 and above, other symbologies). Say that, not "the picture holds no code".
5. **A high `errors_corrected`,** or a format word read with corrected bits, means a damaged symbol was repaired: say so beside the payload.

**Record.** The picture's path and sha256, the payload file, version, level, mask, `errors_corrected`, `located_by`, the tool's version.

**Shows.** What the symbol encodes. **Does not show.** Who made it, when, whether anyone scanned it, or that a link in it was opened.

**Sensitive output.** A payload can be a one-time-password secret, a Wi-Fi passphrase or a login link. It is written to a file, never printed; when `payload_shape` says so, or the case suggests it, run the job with `secret_output: true` and cite the file, not the text.
