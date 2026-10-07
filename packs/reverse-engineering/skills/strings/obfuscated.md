---
id: strings/obfuscated
title: Literal and derived strings as evidence
when: You need strings from a binary, with offsets and a statement of what they can support.
needs: [triage/quarantine]
tools: [ioc_scan]
requires_host: [floss, strings, r2]
---

Use when you need strings out of a binary and must say what they can support. Not for recovering secrets by guessing, or for running a decoder against the sample.

1. Identify format and runtime first. Enumerate the whole file in both encodings and keep offsets: `strings -a -t x SAMPLE` and `strings -a -e l -t x SAMPLE`; record the minimum length. `ioc_scan` searches the needles you give it, single-byte and UTF-16LE: it is not an enumeration of every string. Other encodings, length-prefixed strings and runtime layouts need another reader.
2. **FLOSS** can recover static, stack, tight and decoded strings by analysis and emulation. Recovery is incomplete and depends on format, architecture, compiler and the version you have (`floss -h` lists its modes): record which modes completed. A recovered string is derived, not a literal at a file offset, and not behaviour seen on a host.
3. For each string you rely on, keep its source object, encoding, literal offset or derivation reference, section, and any code reference with its address type (`r2`'s `axt` lists references to an address). A reference supports an inference about possible use; it does not show a connection or an action. "No reference recovered" is bounded by function discovery, indirect addressing and decoding coverage: it does not show the string is unused. Section placement is context, not proof of how a value arrived; separate library text from the author's own.
4. Operational indicators (hosts, paths, keys) need corroboration from host, memory or network artefacts.

Only if you must decode a blob or compare samples, read `strings/decoding-and-similarity`.

Sensitive output: strings, `ioc_scan` snippets and FLOSS output can contain credentials and keys. Run those jobs with `secret_output: true`; report place, kind and length, never the value, a fragment or a hash.

Shows: byte strings and where they sit. Does not show: use, origin or intent. Record: command, encoding, minimum length, tool versions, a reference to the complete output.
