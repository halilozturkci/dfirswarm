---
id: artifacts/biome
title: Biome streams and SEGB framing
when: An activity question depends on a macOS Biome stream, or segb_read answered.
needs: []
tools: [segb_read]
requires_host: []
---

Use when an answer depends on Biome stream files (SEGB containers) under a user's `Library/Biome/` or a system location for them. Not for KnowledgeC, which is SQLite (`artifacts/knowledgec`), and not to carry over what an iOS Biome stream means.

**Framing is not payload.** `segb_read` decodes the framing of SEGB1 and SEGB2 files: frames, offsets, record state and the container times. It shows the payload only as protobuf tags (field number, wire type, offset, length), with no value, string or byte, and `confidence` says how little a clean walk proves, since any bytes can parse as protobuf by chance. What a field means, its unit and its event time are not decoded. The mobile pack's `ios/biome-segb`, if loaded, separates framing from payload, and iOS semantics do not carry over.

**What was not verified.** The two layouts come from public reverse-engineering notes and were never checked here against Apple's own description or a real sample; each answer repeats this as `layout_basis`. A file with neither magic is `unsupported`, a file that fails its bounds is reported as failing the layout and the answer is `partial`. Both are parser outcomes, not empty streams.

**State and time.** `state_raw` 1 and 3 are also named written and deleted, as the notes do; any other number is raw only. A deleted state is a record's lifecycle in storage, not proof that a person deleted anything. `time1_raw` and `time2_raw` are container times (SEGB2 has one per frame). Which of them is the write time or a harvest time is not established, and neither is the payload's own time, which lives inside the payload. A container time is not the time of the event; keep each beside its raw number.

**Provenance.** `stream_from_path` is the last directories of the path in the examiner's copy, not a field of the file. A directory name does not say which device or application wrote a record: decide that before you attribute one to this Mac, as for KnowledgeC rows.

**Coverage.** Count streams and files read, `unsupported` and failing files, and frames walked (`resume.skip_frames` and `next_file` continue a stopped read). A stream with no frames, or no stream, is not absence of the activity elsewhere.

Shows: that a stream held a frame in a recorded state at an offset, with the container times. Does not show: a person acting, what the payload recorded, the event time, or activity absent from the streams acquired.
Record: stream and file path, frame offset, payload offset and length, `state_raw`, both times raw and converted, `layout_basis`, `status` and `problems`.
Sensitive output: payloads can hold message text, URLs and identifiers. `segb_read` shows none of them; a payload decoder is run as a job with `secret_output: true`, and a note cites the offset, never a value.
