---
id: strings/discipline
title: A string in memory is an observation
when: Any claim built on text found in a memory image.
needs: []
card: ioc_scan and chunk_needles {"path": "<file>", "needles": "<a>|<b>"} search only the needles given, ASCII and UTF-16LE, case-sensitive, in stored bytes. Read status (partial says where to go on), then all_results, not the inline page. Context only with {"write_values": true} in a secret_output job. Cite offset, address space, encoding and method. Does not show: that anything ran, connected or was typed.
tools: [ioc_scan, chunk_needles]
requires_host: [strings]
---

Use when a claim rests on text found in memory. Not for process lists (`processes/injection`).

The same bytes reach memory from places unrelated to any process acting:

- an antivirus signature file, loaded into the scanner's memory,
- a browser cache, or a page the user never clicked,
- a log line the logging service holds,
- a file the indexer read,
- an examiner's tooling, running during acquisition.

A string is an observation; report its provenance: the source
object, the offset **and the address space it is in**, the encoding and the method.
Attribute the string to a process only when a validated mapping supports it; a
shared page can have more than one mapping. A file offset must not be
reported as a process virtual address, or the other way round.

Three rules:

1. **Search the encodings explicitly.** Windows holds most strings wide, and a
   search of ASCII alone misses paths, command lines and URLs. `ioc_scan` and
   `chunk_needles` take the needles you give them and search them as ASCII and as
   UTF-16LE, byte for byte (case matters); neither reads compressed or fragmented
   text. `strings -a -t d -e l IMAGE` lists UTF-16LE text with decimal offsets (GNU binutils: check `strings --help`). Record the needles,
   encodings, case variants, byte range and whether the scan finished. `ioc_scan`
   deduplicates hits with alike snippets by default (`unique_only`): set it to
   false when each occurrence's offset matters, and keep the whole paged result.
2. **Context shows what kind of thing you are looking at**, a command line, a log
   line or a list of signatures. It can also be the secret: keep the surrounding
   bytes in a job run with `secret_output: true` and describe their type in shared
   prose, without a password, token, private key or a URL that carries one. Context tests an interpretation; it can still be
   unrelated or fragmented.
3. **A hit with no locator is not evidence.** A reproducible finding has the
   evidence reference, an offset in a named address space, the encoding and the
   extraction method. An offset without its source object does not let anyone go
   back and look.

When a string is all you have, say that. "The domain was present in memory at
offset 0x… of the image, in a region that could not be attributed to a process, and
no artefact on disk corroborates it" is a complete and defensible answer.

**Sensitive output.** The bytes around a match, and `strings` output, can hold
credentials; run these as jobs with `secret_output: true` and read
`credentials/material`.

**Does not show.** That anything ran, connected or was typed, or an intent; that the text was
put there by the process that holds it; that a search which found nothing covers
other encodings, compression or text split across pages.
