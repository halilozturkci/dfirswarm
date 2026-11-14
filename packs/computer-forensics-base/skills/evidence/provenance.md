---
id: evidence/provenance
title: Hash domains and the provenance chain
when: Quoting or comparing a digest, or tracing a result to an exhibit.
needs: []
tools: [check_inputs, image_verify, icat_extract, archive_extract, sqlite_snapshot]
requires_host: [ewfinfo, ewfverify]
---

Use when a hash is quoted, compared or inherited, or a result must be traced to what was delivered. Not for a hash of a secret (never written).

A digest names a set of bytes, not "the evidence". Say which set.

**The domains, each its own bytes:**
1. The delivered container file or each of its segments (what `check_inputs` hashes against `inputs.json`, the run's baseline, taken when the run copied or bound the exhibit).
2. The decoded media stream behind a container. An imager's stored digest covers what its record says it covered: read the acquisition record (`ewfinfo` prints an E01's); `image_verify` wraps `ewfverify`, which re-reads the decoded stream against the digest inside, and lists the segments.
3. A volume or byte range inside it: needs the offset and the length, or it names nothing.
4. An extracted object (`icat_extract` sha256 of one record's data, `archive_extract` size, CRC and sha256 per member, `sqlite_snapshot` sha256 of each file of the set).
5. A transformed output: a converted container, a decompressed or decrypted stream, an applied copy, a rendering.

**Rules.**
- Compare two digests only when the algorithm, the byte domain and the length are the same. An imager's MD5 over the media and your sha256 over the segments are not comparable: quote both.
- Each hop of the chain names its source object (`input:`, `job:<id>/...`, `member:...`), the tool and version, the settings and the digest of what it read and wrote. A transformed output without its source digest and its transformation has no provenance.
- A match shows these bytes agree with that baseline. It does not show who made the baseline, that it was made before transfer, that the acquisition was complete, or that the content is true. Byte integrity, authenticity and completeness are three questions.
- A mismatch, a missing segment or a missing digest is recorded as found, with the conclusions it bears on. Do not repair, re-hash into the baseline or replace the input; ask the operator.
- Run `check_inputs` again before the report. A hash taken while the exhibit was live or bound in place is the state at that moment.
- Transfers and hand-offs (who held it, when, by what route) are part of the chain: record what the case supplies, and say where it does not.

**Secrets.** A digest of an object is its identity and may be quoted. A digest of a secret is not: for a key file, a token file, a recovery key or any short object that is itself a secret, cite the sealed reference, the size and the location, and write no digest. A credential store as a file (a password database, a browser profile file) is an object whose digest is its identity; a value read out of it is a secret. `archive_extract` writes none for a member under 128 bytes; do not compute one by hand.

**Record.** Per digest: the algorithm, the byte domain (object, offset, length), the byte count, who supplied the expected value and when, the tool and version, the result.

**Does not show.** That the baseline was right when made, that the media is whole, or that digests over different domains disagree.
