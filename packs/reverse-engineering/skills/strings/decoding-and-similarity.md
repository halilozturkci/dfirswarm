---
id: strings/decoding-and-similarity
title: Decoding blobs and comparing samples by bytes
when: A string looks encoded, or you want to cluster samples by byte similarity.
needs: []
tools: [fuzzy_hash]
requires_host: [ssdeep, tlsh]
---

Use when a string looks encoded or you want to compare samples. Not for evaluating code: nothing recovered is executed, interpreted or imported.

- **Decode** with trusted, non-evaluating transformations, in a job. Keep the source range, the encoding assumptions, the sequence of steps and a reference to the derived object, and validate its structure before classifying it. A PowerShell encoded command is UTF-16LE base64: decode it as data and do not invoke PowerShell on the text. Do not evaluate JavaScript, VBA or Python to simplify it. Cutting blobs out of images is the base pack's `filesystem/carving`.
- **Similarity.** Run `fuzzy_hash` on the original bytes first, and separately on a comparable derived form. SHA-256 identifies bytes; `ssdeep` and `tlsh` measure similarity only, and the tool needs both programs. `tlsh_status: insufficient_input` means the file is too short or uniform: unavailable is not dissimilar. A distance is a lead: shared libraries, packing and padding produce it. Name distinctive shared code or structure before saying family.
- Record the algorithm, each program's version as the tool printed it, the specimen size and every transformation.

Sensitive output: a decoded blob can be a credential or a key. Decode in a job with `secret_output: true`; describe it by place, kind and length.

Shows: byte similarity, and the steps that produced a derived string. Does not show: provenance, authorship or family. Record: ranges, steps, derived-object references, digests with versions.
